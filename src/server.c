/*
 * Copyright (C) Niklaus F.Schen.
 */

#include "server.h"
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "mln_log.h"
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include "connection.h"

static void portal_server_outer_accept_handler(mln_event_t *ev, int fd, void *data);
static void portal_server_close_handler(mln_event_t *ev, int fd, void *data);
static void portal_server_inner_recv_handler(mln_event_t *ev, int fd, void *data);
static void portal_server_outer_recv_handler(mln_event_t *ev, int fd, void *data);
static void portal_server_inner_accept_handler(mln_event_t *ev, int fd, void *data);
static void portal_server_inner_ping_handler(mln_event_t *ev, int fd, void *data);
static void portal_server_send_handler(mln_event_t *ev, int fd, void *data);
static int portal_server_sortAndBuildChain(mln_event_t *ev, portal_connection_t *outerConn, portal_message_t *msg);

void portal_server_entrance(mln_event_t *ev)
{
    struct sockaddr_in addr;
    int outerSock, innerSock, val;

    /*outer*/
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(gOuterPort);
    addr.sin_addr.s_addr = inet_addr(gOuterIP);
    if ((outerSock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        mln_log(error, "socket error. %s\n", strerror(errno));
        abort();
    }
    val = 1;
    if (setsockopt(outerSock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) < 0) {
        mln_log(error, "setsockopt error. %s\n", strerror(errno));
        abort();
    }
    if (bind(outerSock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        mln_log(error, "bind error. %s\n", strerror(errno));
        abort();
    }
    if (listen(outerSock, 32767) < 0) {
        mln_log(error, "listen error. %s\n", strerror(errno));
        abort();
    }

    /*inner*/
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(gInnerPort);
    addr.sin_addr.s_addr = inet_addr(gInnerIP);
    if ((innerSock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        mln_log(error, "socket error. %s\n", strerror(errno));
        abort();
    }
    val = 1;
    if (setsockopt(innerSock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) < 0) {
        mln_log(error, "setsockopt error. %s\n", strerror(errno));
        abort();
    }
    if (bind(innerSock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        mln_log(error, "bind error. %s\n", strerror(errno));
        abort();
    }
    if (listen(innerSock, 32767) < 0) {
        mln_log(error, "listen error. %s\n", strerror(errno));
        abort();
    }

    /*ev*/
    if (mln_event_set_fd(ev, \
                         outerSock, \
                         M_EV_RECV|M_EV_NONBLOCK, \
                         M_EV_UNLIMITED, \
                         NULL, \
                         portal_server_outer_accept_handler) < 0)
    {
        mln_log(error, "No memory.\n");
        abort();
    }
    if (mln_event_set_fd(ev, \
                         innerSock, \
                         M_EV_RECV|M_EV_NONBLOCK, \
                         M_EV_UNLIMITED, \
                         NULL, \
                         portal_server_inner_accept_handler) < 0)
    {
        mln_log(error, "No memory.\n");
        abort();
    }

    mln_event_dispatch(ev);
}

static void portal_server_outer_accept_handler(mln_event_t *ev, int fd, void *data)
{
    char *ip;
    int connfd;
    socklen_t len;
    mln_u16_t port;
    mln_rbtree_node_t *rn;
    portal_message_t *msg;
    struct sockaddr_in addr;
    mln_chain_t *trans = NULL;
    portal_connection_t *conn;
    mln_tcp_conn_t *innerTcpConn;
    portal_connection_t *innerConn = NULL;

    while (1) {
        memset(&addr, 0, sizeof(addr));
        len = sizeof(addr);
        if ((connfd = accept(fd, (struct sockaddr *)&addr, &len)) < 0) {
            if (errno == EINTR || errno == ECONNABORTED) continue;
            if (errno == EAGAIN || errno == EMFILE || errno == ENFILE)
                break;
            mln_log(error, "accept error. %s\n", strerror(errno));
            break;
        }
        ip = inet_ntoa(addr.sin_addr);
        port = ntohs(addr.sin_port);
        if ((conn = portal_connection_new(connfd, ip, port, outer)) == NULL) {
            mln_log(error, "No memory.\n");
            close(connfd);
            break;
        }
        rn = mln_rbtree_search(gOuterSet, gOuterSet->root, conn);
        if (!mln_rbtree_null(rn, gOuterSet)) {
            portal_connection_free(conn);
            mln_log(error, "Connection key conflict.\n");
            close(connfd);
            continue;
        }
        if ((rn = mln_rbtree_new_node(gOuterSet, conn)) == NULL) {
            portal_connection_free(conn);
            mln_log(error, "No memory.\n");
            close(connfd);
            break;
        }
        mln_rbtree_insert(gOuterSet, rn);

        if (!gIsPositive) {
            innerConn = portal_connection_getInnerConn();
            if (innerConn == NULL) {
                mln_rbtree_delete(gOuterSet, rn);
                mln_rbtree_free_node(gOuterSet, rn);
                mln_log(error, "No inner connection available.\n");
                close(connfd);
                break;
            }
            msg = portal_connection_getMsg(conn);
            msg = portal_msg_packUpMsg(msg, \
                                       NULL, \
                                       portal_connection_getLocalKey(conn), \
                                       portal_connection_getRemoteKey(conn), \
                                       PORTAL_MSG_TYPE_ESTABLISH, \
                                       0, 0);
            if ((trans = portal_msg_msg2chain(portal_connection_getPool(innerConn), msg)) == NULL) {
                mln_log(error, "No memory.\n");
                mln_rbtree_delete(gOuterSet, rn);
                mln_rbtree_free_node(gOuterSet, rn);
                close(connfd);
                break;
            }
        }

        if (mln_event_set_fd(ev, \
                             connfd, \
                             M_EV_RECV|M_EV_NONBLOCK, \
                             gOuterTimeout, \
                             conn, \
                             portal_server_outer_recv_handler) < 0)
        {
            if (trans != NULL) mln_chain_pool_release(trans);
            mln_rbtree_delete(gOuterSet, rn);
            mln_rbtree_free_node(gOuterSet, rn);
            mln_log(error, "No memory.\n");
            close(connfd);
            break;
        }
        mln_event_set_fd_timeout_handler(ev, connfd, conn, portal_server_close_handler);

        if (trans != NULL) {
            innerTcpConn = portal_connection_getTcpConn(innerConn);
            mln_tcp_conn_append(innerTcpConn, trans, M_C_SEND);
            mln_event_set_fd(ev, \
                             mln_tcp_conn_get_fd(innerTcpConn), \
                             M_EV_SEND|M_EV_NONBLOCK|M_EV_APPEND|M_EV_ONESHOT, \
                             M_EV_UNLIMITED, \
                             innerConn, \
                             portal_server_send_handler);

        }

        mln_log(report, "Outer %s:%u Connected.\n", ip, port);
    }
}

static void portal_server_outer_recv_handler(mln_event_t *ev, int fd, void *data)
{
    int rc, err;
    portal_message_t *msg;
    mln_chain_t *c, *trans;
    mln_tcp_conn_t *outerTcpConn;
    mln_tcp_conn_t *innerTcpConn;
    portal_connection_t *outerConn = (portal_connection_t *)data;
    portal_connection_t *innerConn = portal_connection_getInnerConn();
    mln_u64_t seqHigh = 0, seqLow = 0;

    if (innerConn == NULL) {
        portal_server_close_handler(ev, fd, data);
        return;
    }

    outerTcpConn = portal_connection_getTcpConn(outerConn);
    innerTcpConn = portal_connection_getTcpConn(innerConn);

    rc = mln_tcp_conn_recv(outerTcpConn, M_C_TYPE_MEMORY);
    err = errno;
    c = mln_tcp_conn_remove(outerTcpConn, M_C_RECV);
    while (c != NULL) {
        seqLow = outerConn->sndSeqLow++;
        if (outerConn->sndSeqLow == 0) ++outerConn->sndSeqHigh;
        seqHigh = outerConn->sndSeqHigh;
        msg = portal_msg_packUpMsg(portal_connection_getMsg(outerConn), \
                                   &c, \
                                   portal_connection_getLocalKey(outerConn), \
                                   portal_connection_getRemoteKey(outerConn), \
                                   PORTAL_MSG_TYPE_DATA, \
                                   seqHigh, seqLow);
        if ((trans = portal_msg_msg2chain(portal_connection_getPool(innerConn), msg)) == NULL) {
            mln_log(error, "No memory.\n");
            if (c != NULL) mln_chain_pool_release_all(c);
            portal_server_close_handler(ev, fd, data);
            return;
        }
        mln_tcp_conn_append(innerTcpConn, trans, M_C_SEND);
        mln_event_set_fd(ev, \
                         mln_tcp_conn_get_fd(innerTcpConn), \
                         M_EV_SEND|M_EV_NONBLOCK|M_EV_APPEND|M_EV_ONESHOT, \
                         M_EV_UNLIMITED, \
                         innerConn, \
                         portal_server_send_handler);
    }
    if (rc == M_C_ERROR) {
        if (err != ECONNRESET) {
            mln_log(error, "recv error. %s\n", strerror(err));
        }
        portal_server_close_handler(ev, fd, data);
    } else if (rc == M_C_CLOSED) {
        portal_server_close_handler(ev, fd, data);
    } else {
        if (mln_tcp_conn_get_head(outerTcpConn, M_C_SEND) == NULL) {
            mln_event_set_fd(ev, \
                             fd, \
                             M_EV_RECV|M_EV_NONBLOCK, \
                             gOuterTimeout, \
                             outerConn, \
                             portal_server_outer_recv_handler);
            mln_event_set_fd_timeout_handler(ev, fd, data, portal_server_close_handler);
        }
    }
}

static void portal_server_close_handler(mln_event_t *ev, int fd, void *data)
{
    mln_chain_t *trans;
    mln_rbtree_t *tree;
    mln_rbtree_node_t *rn;
    portal_message_t *msg;
    portal_connection_t *innerConn = NULL;
    portal_connection_t *conn = (portal_connection_t *)data;
    mln_u64_t seqHigh = 0, seqLow = 0;

    if (portal_connection_getType(conn) == outer) {
        tree = gOuterSet;
        innerConn = portal_connection_getInnerConn();
    } else {
        portal_connection_moveChain(ev, conn, portal_server_inner_recv_handler, portal_server_send_handler);
        tree = gInnerSet;
    }
    if (innerConn != NULL) {
        mln_tcp_conn_t *innerTcpConn = portal_connection_getTcpConn(innerConn);
        seqLow = conn->sndSeqLow++;
        if (conn->sndSeqLow == 0) ++conn->sndSeqHigh;
        seqHigh = conn->sndSeqHigh;
        msg = portal_msg_packUpMsg(portal_connection_getMsg(conn), \
                                   NULL, \
                                   portal_connection_getLocalKey(conn), \
                                   portal_connection_getRemoteKey(conn), \
                                   PORTAL_MSG_TYPE_BYE, \
                                   seqHigh, seqLow);
        if ((trans = portal_msg_msg2chain(portal_connection_getPool(innerConn), msg)) == NULL) {
            mln_log(error, "No memory.\n");
            abort();
        }
        mln_tcp_conn_append(innerTcpConn, trans, M_C_SEND);
        mln_event_set_fd(ev, \
                         mln_tcp_conn_get_fd(innerTcpConn), \
                         M_EV_SEND|M_EV_NONBLOCK|M_EV_APPEND|M_EV_ONESHOT, \
                         M_EV_UNLIMITED, \
                         innerConn, \
                         portal_server_send_handler);
    }
    mln_event_set_fd(ev, fd, M_EV_CLR, M_EV_UNLIMITED, conn, NULL);
    rn = mln_rbtree_search(tree, tree->root, conn);
    if (!mln_rbtree_null(rn, tree)) {
        mln_rbtree_delete(tree, rn);
        mln_rbtree_free_node(tree, rn);
    } else {
        portal_connection_free(conn);
    }
    close(fd);
}

static void portal_server_inner_accept_handler(mln_event_t *ev, int fd, void *data)
{
    char *ip;
    int connfd;
    socklen_t len;
    mln_u16_t port;
    mln_rbtree_node_t *rn;
    struct sockaddr_in addr;
    portal_connection_t *conn;

    while (1) {
        memset(&addr, 0, sizeof(addr));
        len = sizeof(addr);
        if ((connfd = accept(fd, (struct sockaddr *)&addr, &len)) < 0) {
            if (errno == EINTR || errno == ECONNABORTED) continue;
            if (errno == EAGAIN || errno == EMFILE || errno == ENFILE)
                break;
            mln_log(error, "accept error. %s\n", strerror(errno));
            break;
        }
        ip = inet_ntoa(addr.sin_addr);
        port = ntohs(addr.sin_port);
        if ((conn = portal_connection_new(connfd, ip, port, inner)) == NULL) {
            mln_log(error, "No memory.\n");
            close(connfd);
            break;
        }
        rn = mln_rbtree_search(gInnerSet, gInnerSet->root, conn);
        if (!mln_rbtree_null(rn, gInnerSet)) {
            portal_connection_free(conn);
            mln_log(error, "Connection key conflict.\n");
            close(connfd);
            continue;
        }
        if ((rn = mln_rbtree_new_node(gInnerSet, conn)) == NULL) {
            portal_connection_free(conn);
            mln_log(error, "No memory.\n");
            close(connfd);
            break;
        }
        mln_rbtree_insert(gInnerSet, rn);
        if (mln_event_set_fd(ev, \
                             connfd, \
                             M_EV_RECV|M_EV_NONBLOCK, \
                             gInnerTimeout, \
                             conn, \
                             portal_server_inner_recv_handler) < 0)
        {
            mln_rbtree_delete(gInnerSet, rn);
            mln_rbtree_free_node(gInnerSet, rn);
            mln_log(error, "No memory.\n");
            close(connfd);
            break;
        }
        mln_event_set_fd_timeout_handler(ev, connfd, conn, portal_server_inner_ping_handler);
        mln_log(report, "Inner %s:%u Connected.\n", ip, port);
    }
}

static void portal_server_inner_ping_handler(mln_event_t *ev, int fd, void *data)
{
    mln_chain_t *trans;
    portal_connection_t *innerConn = (portal_connection_t *)data;
    portal_message_t *msg = portal_connection_getMsg(innerConn);
    mln_tcp_conn_t *innerTcpConn = portal_connection_getTcpConn(innerConn);

    msg = portal_msg_packUpMsg(msg, \
                               NULL, \
                               portal_connection_getLocalKey(innerConn), \
                               portal_connection_getRemoteKey(innerConn), \
                               PORTAL_MSG_TYPE_HELLO, \
                               0, 0);
    if ((trans = portal_msg_msg2chain(portal_connection_getPool(innerConn), msg)) == NULL) {
        mln_log(error, "No memory.\n");
        portal_server_close_handler(ev, fd, data);
        return;
    }
    mln_tcp_conn_append(innerTcpConn, trans, M_C_SEND);
    mln_event_set_fd(ev, \
                     mln_tcp_conn_get_fd(innerTcpConn), \
                     M_EV_SEND|M_EV_NONBLOCK|M_EV_APPEND|M_EV_ONESHOT, \
                     M_EV_UNLIMITED, \
                     innerConn, \
                     portal_server_send_handler);
}

static int portal_server_sortAndBuildChain(mln_event_t *ev, portal_connection_t *outerConn, portal_message_t *msg)
{
    mln_chain_t *c = NULL;
    mln_tcp_conn_t *outerTcpConn = portal_connection_getTcpConn(outerConn);
    memcpy(portal_connection_getRemoteKey(outerConn), msg->clientKey, __M_SHA_BUFLEN);
    portal_message_t *dup = portal_message_dup(msg);
    if (dup == NULL) {
        mln_log(error, "No memory.\n");
        return -1;
    }
    if (portal_connection_addMsgBuildChain(outerConn, dup, &c) < 0) {
        return -1;
    }
    if (c != NULL) {
        mln_tcp_conn_append_chain(outerTcpConn, c, NULL, M_C_SEND);
        mln_event_set_fd(ev, \
                         mln_tcp_conn_get_fd(outerTcpConn), \
                         M_EV_SEND|M_EV_NONBLOCK|M_EV_APPEND|M_EV_ONESHOT, \
                         M_EV_UNLIMITED, \
                         outerConn, \
                         portal_server_send_handler);
    }
    return 0;
}

static void portal_server_inner_recv_handler(mln_event_t *ev, int fd, void *data)
{
    portal_connection_t *innerConn = (portal_connection_t *)data;
    portal_connection_t *outerConn, tmp;
    mln_tcp_conn_t *innerTcpConn = portal_connection_getTcpConn(innerConn);
    mln_tcp_conn_t *outerTcpConn;
    mln_chain_t *c, *trans;
    portal_message_t *msg;
    mln_rbtree_node_t *rn;
    int rc, err, ret;

    rc = mln_tcp_conn_recv(innerTcpConn, M_C_TYPE_MEMORY);
    err = errno;
    c = mln_tcp_conn_remove(innerTcpConn, M_C_RECV);
again:
    msg = portal_connection_getMsg(innerConn);
    ret = portal_msg_chain2msg(&c, msg);
    if (ret == PORTAL_MSG_RET_OK) {
        if (msg->type == PORTAL_MSG_TYPE_DATA) {
            memcpy(tmp.localKey, msg->serverKey, __M_SHA_BUFLEN);
            rn = mln_rbtree_search(gOuterSet, gOuterSet->root, &tmp);
            if (!mln_rbtree_null(rn, gOuterSet)) {
                outerConn = (portal_connection_t *)(rn->data);
                if (portal_server_sortAndBuildChain(ev, outerConn, msg) < 0) {
                    outerTcpConn = portal_connection_getTcpConn(outerConn);
                    portal_server_close_handler(ev, mln_tcp_conn_get_fd(outerTcpConn), outerConn);
                }
            }
        } else if (msg->type == PORTAL_MSG_TYPE_HELLO) {
            msg = portal_msg_packUpMsg(msg, \
                                       NULL, \
                                       portal_connection_getLocalKey(innerConn), \
                                       portal_connection_getRemoteKey(innerConn), \
                                       PORTAL_MSG_TYPE_ACK, \
                                       0, 0);
            if ((trans = portal_msg_msg2chain(portal_connection_getPool(innerConn), msg)) == NULL) {
                mln_log(error, "No memory.\n");
                if (c != NULL) mln_tcp_conn_append_chain(innerTcpConn, c, NULL, M_C_RECV);
                portal_server_close_handler(ev, fd, data);
                return;
            }
            mln_tcp_conn_append(innerTcpConn, trans, M_C_SEND);
            mln_event_set_fd(ev, \
                             mln_tcp_conn_get_fd(innerTcpConn), \
                             M_EV_SEND|M_EV_NONBLOCK|M_EV_APPEND|M_EV_ONESHOT, \
                             M_EV_UNLIMITED, \
                             innerConn, \
                             portal_server_send_handler);
        } else if (msg->type == PORTAL_MSG_TYPE_ACK) {
            /*do nothing*/
        } else if (msg->type == PORTAL_MSG_TYPE_BYE) {
            memcpy(tmp.localKey, msg->serverKey, __M_SHA_BUFLEN);
            rn = mln_rbtree_search(gOuterSet, gOuterSet->root, &tmp);
            if (!mln_rbtree_null(rn, gOuterSet)) {
                outerConn = (portal_connection_t *)(rn->data);
                outerTcpConn = portal_connection_getTcpConn(outerConn);
                if (outerConn->rcvSeqHigh == msg->seqHigh && \
                    outerConn->rcvSeqLow == msg->seqLow && \
                    mln_tcp_conn_get_head(outerTcpConn, M_C_SEND) == NULL)
                {
                    portal_server_close_handler(ev, mln_tcp_conn_get_fd(outerTcpConn), outerConn);
                } else {
                    portal_connection_setClose(outerConn, msg->seqHigh, msg->seqLow);
                }
            }
        } else {
            mln_log(error, "No such type. %x\n", msg->type);
            if (c != NULL) mln_chain_pool_release_all(c);
            portal_server_close_handler(ev, fd, data);
            return;
        }
        portal_msg_init(portal_connection_getMsg(innerConn));
        goto again;
    } else if (ret == PORTAL_MSG_RET_ERROR) {
        if (c != NULL) mln_chain_pool_release_all(c);
        portal_server_close_handler(ev, fd, data);
        return;
    }
    /*PORTAL_MSG_RET_AGAIN*/
    if (c != NULL) {
        mln_tcp_conn_append_chain(innerTcpConn, c, NULL, M_C_RECV);
    }
    if (rc == M_C_ERROR) {
        mln_log(error, "recv error. %s\n", strerror(err));
        portal_server_close_handler(ev, fd, data);
    } else if (rc == M_C_CLOSED) {
        portal_server_close_handler(ev, fd, data);
    }
}

static void portal_server_send_handler(mln_event_t *ev, int fd, void *data)
{
    int rc;
    mln_chain_t *c;
    portal_connection_t *conn = (portal_connection_t *)data;
    mln_tcp_conn_t *tcpConn = portal_connection_getTcpConn(conn);

    rc = mln_tcp_conn_send(tcpConn);
    if (rc == M_C_FINISH || rc == M_C_NOTYET) {
        c = mln_tcp_conn_remove(tcpConn, M_C_SENT);
        mln_chain_pool_release_all(c);
        if (rc == M_C_NOTYET && mln_tcp_conn_get_head(tcpConn, M_C_SEND) != NULL) {
            mln_event_set_fd(ev, \
                             fd, \
                             M_EV_SEND|M_EV_NONBLOCK|M_EV_APPEND|M_EV_ONESHOT, \
                             M_EV_UNLIMITED, \
                             data, \
                             portal_server_send_handler);
        } else {
            if (portal_connection_shouldClose(conn)) {
                portal_server_close_handler(ev, fd, data);
                return;
            }
            if (portal_connection_getType(conn) == outer) {
                mln_event_set_fd(ev, \
                                 fd, \
                                 M_EV_RECV|M_EV_NONBLOCK, \
                                 gOuterTimeout, \
                                 data, \
                                 portal_server_outer_recv_handler);
                mln_event_set_fd_timeout_handler(ev, fd, data, portal_server_close_handler);
            } else {
                mln_event_set_fd(ev, \
                                 fd, \
                                 M_EV_RECV|M_EV_NONBLOCK, \
                                 gInnerTimeout, \
                                 data, \
                                 portal_server_inner_recv_handler);
                mln_event_set_fd_timeout_handler(ev, fd, data, portal_server_inner_ping_handler);
            }
        }
    } else if (rc == M_C_ERROR) {
        mln_log(error, "send error. %s\n", strerror(errno));
        portal_server_close_handler(ev, fd, data);
    } else {/*M_C_CLOSED*/
        portal_server_close_handler(ev, fd, data);
    }
}



