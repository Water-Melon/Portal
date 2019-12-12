/*
 * Copyright (C) Niklaus F.Schen.
 */

#include "client.h"
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "mln_log.h"
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <fcntl.h>

static int portal_client_connect(mln_event_t *ev, conn_type_t type, portal_message_t *msg);
static void portal_client_connect_test(mln_event_t *ev, int fd, void *data, conn_type_t type);
static void portal_client_inner_connect_test(mln_event_t *ev, int fd, void *data);
static void portal_client_outer_connect_test(mln_event_t *ev, int fd, void *data);
static void portal_client_fdClose_handler(mln_event_t *ev, int fd, void *data);
static void portal_client_connect_innerRetry(mln_event_t *ev, void *data);
static void portal_client_outer_recv_handler(mln_event_t *ev, int fd, void *data);
static void portal_client_inner_recv_handler(mln_event_t *ev, int fd, void *data);
static void portal_client_send_handler(mln_event_t *ev, int fd, void *data);
static void portal_client_inner_ping_handler(mln_event_t *ev, int fd, void *data);
static void portal_client_close_handler(mln_event_t *ev, int fd, void *data);
static int portal_client_sortAndBuildChain(mln_event_t *ev, portal_connection_t *outerConn, portal_message_t *msg);

static fdClose_dataSet_t *fdClose_dataSet_new(conn_type_t type, void *data)
{
    fdClose_dataSet_t *ret = (fdClose_dataSet_t *)malloc(sizeof(fdClose_dataSet_t));
    if (ret == NULL) return NULL;
    ret->type = type;
    ret->data = data;
    return ret;
}

static void fdClose_dataSet_free(fdClose_dataSet_t *data)
{
    if (data == NULL) return;
    if (data->data != NULL) {
        portal_message_free((portal_message_t *)(data->data));
    }
    free(data);
}

void portal_client_entrance(mln_event_t *ev)
{
    signal(SIGPIPE, SIG_IGN);
    mln_sauto_t i;
    for (i = 0; i < gTunnelNum; ++i) {
        portal_client_connect(ev, inner, NULL);
    }
    mln_event_dispatch(ev);
}

static int portal_client_connect(mln_event_t *ev, conn_type_t type, portal_message_t *msg)
{
    int sockfd, flg;
    struct sockaddr_in addr;
    mln_u16_t port = type==outer? gOuterPort: gInnerPort;
    char *ip = type==outer? gOuterIP: gInnerIP;
    fdClose_dataSet_t *dataSet;

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        mln_log(error, "socket error. %s\n", strerror(errno));
        return type==inner? \
                   mln_event_set_timer(ev, gRetryTimeout, NULL, portal_client_connect_innerRetry): \
                   -1;
    }
    flg = fcntl(sockfd, F_GETFL, NULL);
    fcntl(sockfd, F_SETFL, flg | O_NONBLOCK);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);
    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0 && errno != EINPROGRESS) {
        mln_log(error, "connect error. %s\n", strerror(errno));
        close(sockfd);
        return type==inner? \
                   mln_event_set_timer(ev, gRetryTimeout, NULL, portal_client_connect_innerRetry): \
                   -1;
    }
    if ((dataSet = fdClose_dataSet_new(type, msg)) == NULL) {
        mln_log(error, "No memory.\n");
        close(sockfd);
        return type==inner? \
                   mln_event_set_timer(ev, gRetryTimeout, NULL, portal_client_connect_innerRetry): \
                   -1;
    }
    portal_client_connect_test(ev, sockfd, dataSet, type);
    return 0;
}

static void portal_client_inner_connect_test(mln_event_t *ev, int fd, void *data)
{
    portal_client_connect_test(ev, fd, data, inner);
}

static void portal_client_outer_connect_test(mln_event_t *ev, int fd, void *data)
{
    portal_client_connect_test(ev, fd, data, outer);
}

static void portal_client_connect_test(mln_event_t *ev, int fd, void *data, conn_type_t type)
{
    ev_fd_handler handler;
    int err = 0;
    socklen_t len = sizeof(err);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0) {
        mln_log(error, "getsockopt error. %s\n", strerror(errno));
        portal_client_fdClose_handler(ev, fd, data);
        return;
    }
    if (err) {
        if (err == EINPROGRESS) {
            handler = type==inner? portal_client_inner_connect_test: portal_client_outer_connect_test;
            mln_event_set_fd(ev, \
                             fd, \
                             M_EV_SEND|M_EV_RECV|M_EV_NONBLOCK, \
                             M_EV_UNLIMITED, \
                             data, \
                             handler);
        } else {
            mln_log(error, "connect failed. %s\n", strerror(err));
            portal_client_fdClose_handler(ev, fd, data);
        }
        return;
    }

    int rc;
    mln_rbtree_t *tree;
    mln_rbtree_node_t *rn;
    portal_connection_t *conn;
    mln_u16_t port = type==outer? gOuterPort: gInnerPort;
    char *ip = type==outer? gOuterIP: gInnerIP;
    if ((conn = portal_connection_new(fd, ip, port, type)) == NULL) {
        mln_log(error, "No memory or hash key conflict.\n");
        portal_client_fdClose_handler(ev, fd, data);
        return;
    }
    tree = type == outer? gOuterSet: gInnerSet;
    if ((rn = mln_rbtree_new_node(tree, conn)) == NULL) {
        mln_log(error, "No memory.\n");
        portal_connection_free(conn);
        portal_client_fdClose_handler(ev, fd, data);
        return;
    }
    mln_rbtree_insert(tree, rn);
    if (type == outer) {
        rc = mln_event_set_fd(ev, \
                              fd, \
                              M_EV_RECV|M_EV_NONBLOCK, \
                              M_EV_UNLIMITED, \
                              conn, \
                              portal_client_outer_recv_handler);
    } else {
        rc = mln_event_set_fd(ev, \
                              fd, \
                              M_EV_RECV|M_EV_NONBLOCK, \
                              gInnerTimeout, \
                              conn, \
                              portal_client_inner_recv_handler);
    }
    if (rc < 0) {
        mln_log(error, "No memory.\n");
        mln_rbtree_delete(tree, rn);
        mln_rbtree_free_node(tree, rn);
        portal_client_fdClose_handler(ev, fd, data);
        return;
    }
    if (type == inner) {
        if (gInnerTimeout >= 0) {
            mln_event_set_fd_timeout_handler(ev, fd, conn, portal_client_inner_ping_handler);
        }
    } else if (data != NULL) {/*outer*/
        fdClose_dataSet_t *dataSet = (fdClose_dataSet_t *)data;
        portal_message_t *msg = (portal_message_t *)(dataSet->data);
        if (msg->type != PORTAL_MSG_TYPE_ESTABLISH) {
            if (portal_client_sortAndBuildChain(ev, conn, msg) < 0) {
                mln_tcp_conn_t *tcpConn = portal_connection_getTcpConn(conn);
                portal_client_close_handler(ev, mln_tcp_conn_get_fd(tcpConn), conn);
            }
            fdClose_dataSet_free(dataSet);
        } else {
            memcpy(portal_connection_getRemoteKey(conn), msg->serverKey, PORTAL_KEY_LEN);
            fdClose_dataSet_free(dataSet);
        }
    }
}

static void portal_client_connect_innerRetry(mln_event_t *ev, void *data)
{
    if (portal_client_connect(ev, inner, NULL) < 0) {
        mln_event_set_timer(ev, gRetryTimeout, NULL, portal_client_connect_innerRetry);
    }
}

static void portal_client_fdClose_handler(mln_event_t *ev, int fd, void *data)
{
    if (data != NULL) {
        fdClose_dataSet_t *dataSet = (fdClose_dataSet_t *)data;
        if (dataSet->type == inner) {
            mln_event_set_timer(ev, gRetryTimeout, NULL, portal_client_connect_innerRetry);
        }
        fdClose_dataSet_free(dataSet);
    } else {
        mln_event_set_timer(ev, gRetryTimeout, NULL, portal_client_connect_innerRetry);
    }
    mln_event_set_fd(ev, fd, M_EV_CLR, M_EV_UNLIMITED, NULL, NULL);
    close(fd);
}

static void portal_client_outer_recv_handler(mln_event_t *ev, int fd, void *data)
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
        portal_client_close_handler(ev, fd, data);
        return;
    }

    outerTcpConn = portal_connection_getTcpConn(outerConn);
    innerTcpConn = portal_connection_getTcpConn(innerConn);

    rc = mln_tcp_conn_recv(outerTcpConn, M_C_TYPE_MEMORY);
    err = errno;
    c = mln_tcp_conn_remove(outerTcpConn, M_C_RECV);
    while (c != NULL) {
        seqLow = outerConn->sndSeqLow++;
        seqHigh = outerConn->sndSeqHigh;
        if (outerConn->sndSeqLow == 0) ++outerConn->sndSeqHigh;
        msg = portal_msg_packUpMsg(portal_connection_getMsg(outerConn), \
                                   &c, \
                                   portal_connection_getRemoteKey(outerConn), \
                                   portal_connection_getLocalKey(outerConn), \
                                   PORTAL_MSG_TYPE_DATA, \
                                   seqHigh, seqLow);
        if ((trans = portal_msg_msg2chain(portal_connection_getPool(innerConn), msg)) == NULL) {
            mln_log(error, "No memory.\n");
            if (c != NULL) mln_tcp_conn_append_chain(outerTcpConn, c, NULL, M_C_RECV);;
            portal_client_close_handler(ev, fd, data);
            return;
        }
        mln_tcp_conn_append(innerTcpConn, trans, M_C_SEND);
        mln_event_set_fd(ev, \
                         mln_tcp_conn_get_fd(innerTcpConn), \
                         M_EV_SEND|M_EV_NONBLOCK|M_EV_APPEND|M_EV_ONESHOT, \
                         M_EV_UNLIMITED, \
                         innerConn, \
                         portal_client_send_handler);
    }
    if (rc == M_C_ERROR) {
        if (c != NULL) mln_tcp_conn_append_chain(outerTcpConn, c, NULL, M_C_RECV);;
        if (err != ECONNRESET) {
            mln_log(error, "recv error. %s\n", strerror(err));
        }
        portal_client_close_handler(ev, fd, data);
    } else if (rc == M_C_CLOSED) {
        if (c != NULL) mln_tcp_conn_append_chain(outerTcpConn, c, NULL, M_C_RECV);;
        portal_client_close_handler(ev, fd, data);
    }
}

static void portal_client_inner_recv_handler(mln_event_t *ev, int fd, void *data)
{
    portal_connection_t *innerConn = (portal_connection_t *)data;
    portal_connection_t *outerConn, tmp;
    mln_tcp_conn_t *innerTcpConn = portal_connection_getTcpConn(innerConn);
    mln_tcp_conn_t *outerTcpConn;
    mln_chain_t *c, *trans;
    portal_message_t *msg, *msgdata;
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
            if (msg->clientKey[0] == 0) {
newconn:
                if ((msgdata = portal_message_dup(msg)) == NULL) {
                    mln_log(error, "No memory.\n");
                    portal_connection_t tmp;
                    tmp.type = outer;
                    tmp.localKey[0] = 0;
                    memcpy(tmp.remoteKey, msg->serverKey, PORTAL_KEY_LEN);
                    portal_client_close_handler(ev, -1, &tmp);
                } else if (portal_client_connect(ev, outer, msgdata) < 0) {
                    portal_message_free(msgdata);
                    portal_connection_t tmp;
                    tmp.type = outer;
                    tmp.localKey[0] = 0;
                    memcpy(tmp.remoteKey, msg->serverKey, PORTAL_KEY_LEN);
                    portal_client_close_handler(ev, -1, &tmp);
                }
            } else {
                memcpy(tmp.localKey, msg->clientKey, PORTAL_KEY_LEN);
                rn = mln_rbtree_search(gOuterSet, gOuterSet->root, &tmp);
                if (!mln_rbtree_null(rn, gOuterSet)) {
                    outerConn = (portal_connection_t *)(rn->data);
                    if (portal_client_sortAndBuildChain(ev, outerConn, msg) < 0) {
                        mln_tcp_conn_t *outerTcpConn = portal_connection_getTcpConn(outerConn);
                        portal_client_close_handler(ev, mln_tcp_conn_get_fd(outerTcpConn), outerConn);
                    }
                }
            }
        } else if (msg->type == PORTAL_MSG_TYPE_HELLO) {
            msg = portal_msg_packUpMsg(msg, \
                                       NULL, \
                                       portal_connection_getRemoteKey(innerConn), \
                                       portal_connection_getLocalKey(innerConn), \
                                       PORTAL_MSG_TYPE_ACK, \
                                       0, 0);
            if ((trans = portal_msg_msg2chain(portal_connection_getPool(innerConn), msg)) == NULL) {
                mln_log(error, "No memory.\n");
                if (c != NULL) mln_tcp_conn_append_chain(innerTcpConn, c, NULL, M_C_RECV);
                portal_client_close_handler(ev, fd, data);
                return;
            }
            mln_tcp_conn_append(innerTcpConn, trans, M_C_SEND);
            mln_event_set_fd(ev, \
                             mln_tcp_conn_get_fd(innerTcpConn), \
                             M_EV_SEND|M_EV_NONBLOCK|M_EV_APPEND|M_EV_ONESHOT, \
                             M_EV_UNLIMITED, \
                             innerConn, \
                             portal_client_send_handler);
        } else if (msg->type == PORTAL_MSG_TYPE_ACK) {
            /*do nothing*/
        } else if (msg->type == PORTAL_MSG_TYPE_BYE) {
            memcpy(tmp.localKey, msg->clientKey, PORTAL_KEY_LEN);
            rn = mln_rbtree_search(gOuterSet, gOuterSet->root, &tmp);
            if (!mln_rbtree_null(rn, gOuterSet)) {
                outerConn = (portal_connection_t *)(rn->data);
                outerTcpConn = portal_connection_getTcpConn(outerConn);
                if (outerConn->rcvSeqHigh == msg->seqHigh && \
                    outerConn->rcvSeqLow == msg->seqLow && \
                    mln_tcp_conn_get_head(outerTcpConn, M_C_SEND) == NULL)
                {
                    portal_client_close_handler(ev, mln_tcp_conn_get_fd(outerTcpConn), outerConn);
                } else {
                    portal_connection_setClose(outerConn, msg->seqHigh, msg->seqLow);
                }
            }
        } else if (msg->type == PORTAL_MSG_TYPE_ESTABLISH) {
            goto newconn;
        } else {
            mln_log(error, "No such type. %x\n", msg->type);
            if (c != NULL) mln_chain_pool_release_all(c);
            portal_client_close_handler(ev, fd, data);
            return;
        }
        portal_msg_init(portal_connection_getMsg(innerConn));
        goto again;
    } else if (ret == PORTAL_MSG_RET_ERROR) {
        if (c != NULL) mln_chain_pool_release_all(c);
        portal_client_close_handler(ev, fd, data);
        return;
    }
    /*PORTAL_MSG_RET_AGAIN*/
    if (c != NULL) {
        mln_tcp_conn_append_chain(innerTcpConn, c, NULL, M_C_RECV);
    }
    if (rc == M_C_ERROR) {
        mln_log(error, "recv error. %s\n", strerror(err));
        portal_client_close_handler(ev, fd, data);
    } else if (rc == M_C_CLOSED) {
        portal_client_close_handler(ev, fd, data);
    }
}

static void portal_client_send_handler(mln_event_t *ev, int fd, void *data)
{
    int rc;
    mln_chain_t *c;
    portal_connection_t *conn = (portal_connection_t *)data;
    mln_tcp_conn_t *tcpConn = portal_connection_getTcpConn(conn);

    rc = mln_tcp_conn_send(tcpConn);
    if (rc == M_C_FINISH || rc == M_C_NOTYET) {
        c = mln_tcp_conn_remove(tcpConn, M_C_SENT);
        mln_chain_pool_release_all(c);
        if (mln_tcp_conn_get_head(tcpConn, M_C_SEND) != NULL) {
            mln_event_set_fd(ev, \
                             fd, \
                             M_EV_SEND|M_EV_NONBLOCK|M_EV_APPEND|M_EV_ONESHOT, \
                             M_EV_UNLIMITED, \
                             data, \
                             portal_client_send_handler);
        } else {
            if (portal_connection_shouldClose(conn)) {
                portal_client_close_handler(ev, fd, data);
                return;
            }
            if (portal_connection_getType(conn) == outer) {
                mln_event_set_fd(ev, \
                                 fd, \
                                 M_EV_RECV|M_EV_NONBLOCK, \
                                 M_EV_UNLIMITED, \
                                 data, \
                                 portal_client_outer_recv_handler);
            } else {
                mln_event_set_fd(ev, \
                                 fd, \
                                 M_EV_RECV|M_EV_NONBLOCK, \
                                 gInnerTimeout, \
                                 data, \
                                 portal_client_inner_recv_handler);
                if (gInnerTimeout >= 0) {
                    mln_event_set_fd_timeout_handler(ev, fd, data, portal_client_inner_ping_handler);
                }
            }
        }
    } else if (rc == M_C_ERROR) {
        mln_log(error, "send error. %s\n", strerror(errno));
        portal_client_close_handler(ev, fd, data);
    } else {/*M_C_CLOSED*/
        portal_client_close_handler(ev, fd, data);
    }
}

static void portal_client_inner_ping_handler(mln_event_t *ev, int fd, void *data)
{
    mln_chain_t *trans;
    portal_connection_t *innerConn = (portal_connection_t *)data;
    portal_message_t *msg = portal_connection_getMsg(innerConn);
    mln_tcp_conn_t *innerTcpConn = portal_connection_getTcpConn(innerConn);

    msg = portal_msg_packUpMsg(msg, \
                               NULL, \
                               portal_connection_getRemoteKey(innerConn), \
                               portal_connection_getLocalKey(innerConn), \
                               PORTAL_MSG_TYPE_HELLO, \
                               0, 0);
    if ((trans = portal_msg_msg2chain(portal_connection_getPool(innerConn), msg)) == NULL) {
        mln_log(error, "No memory.\n");
        portal_client_close_handler(ev, fd, data);
        return;
    }
    mln_tcp_conn_append(innerTcpConn, trans, M_C_SEND);
    mln_event_set_fd(ev, \
                     mln_tcp_conn_get_fd(innerTcpConn), \
                     M_EV_SEND|M_EV_NONBLOCK|M_EV_APPEND|M_EV_ONESHOT, \
                     M_EV_UNLIMITED, \
                     innerConn, \
                     portal_client_send_handler);
}

static void portal_client_close_handler(mln_event_t *ev, int fd, void *data)
{
    conn_type_t type;
    mln_chain_t *trans;
    mln_rbtree_t *tree;
    mln_rbtree_node_t *rn;
    portal_message_t *msg;
    portal_connection_t *innerConn = NULL;
    portal_connection_t *conn = (portal_connection_t *)data;
    mln_u64_t seqHigh = 0, seqLow = 0;

    type = portal_connection_getType(conn);
    if (type == outer) {
        tree = gOuterSet;
        innerConn = portal_connection_getInnerConn();
    } else {
        portal_connection_moveChain(ev, conn, portal_client_inner_recv_handler, portal_client_send_handler);
        tree = gInnerSet;
    }
    if (innerConn != NULL) {
        mln_tcp_conn_t *innerTcpConn = portal_connection_getTcpConn(innerConn);
        seqLow = conn->sndSeqLow++;
        seqHigh = conn->sndSeqHigh;
        if (conn->sndSeqLow == 0) ++conn->sndSeqHigh;
        msg = portal_msg_packUpMsg(portal_connection_getMsg(conn), \
                                   NULL, \
                                   portal_connection_getRemoteKey(conn), \
                                   portal_connection_getLocalKey(conn), \
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
                         portal_client_send_handler);
    }
    if (fd >= 0) {
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
    if (type == inner) {
        mln_event_set_timer(ev, gRetryTimeout, NULL, portal_client_connect_innerRetry);
    }
}

static int portal_client_sortAndBuildChain(mln_event_t *ev, portal_connection_t *outerConn, portal_message_t *msg)
{
    mln_chain_t *c = NULL;
    mln_tcp_conn_t *outerTcpConn = portal_connection_getTcpConn(outerConn);
    portal_message_t *dup;

    memcpy(portal_connection_getRemoteKey(outerConn), msg->serverKey, PORTAL_KEY_LEN);
    if ((dup = portal_message_dup(msg)) == NULL) {
        mln_log(error, "No memory.\n");
        return -1;
    }
    if (portal_connection_addMsgBuildChain(outerConn, dup, &c)< 0) {
        return -1;
    }
    if (c != NULL) {
        mln_tcp_conn_append_chain(outerTcpConn, c, NULL, M_C_SEND);
        mln_event_set_fd(ev, \
                         mln_tcp_conn_get_fd(outerTcpConn), \
                         M_EV_SEND|M_EV_NONBLOCK|M_EV_APPEND|M_EV_ONESHOT, \
                         M_EV_UNLIMITED, \
                         outerConn, \
                         portal_client_send_handler);
    }
    return 0;
}



