/*
 * Copyright (C) Niklaus F.Schen.
 */

#include "broadcaster.h"
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "mln_log.h"
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include "connection.h"
#include <signal.h>
#include <fcntl.h>

struct broadcaster_toolset {
    portal_connection_t *sender;
    portal_message_t    *msg;
    mln_event_t         *ev;
};

static void portal_broadcaster_accept_handler(mln_event_t *ev, int fd, void *data);
static void portal_broadcaster_msg_recv_handler(mln_event_t *ev, int fd, void *data);
static void portal_broadcaster_close_handler(mln_event_t *ev, int fd, void *data);
static void portal_broadcaster_send_handler(mln_event_t *ev, int fd, void *data);
static int portal_broadcaster_broadcast(mln_rbtree_node_t *node, void *rn_data, void *udata);

void portal_broadcaster_entrance(mln_event_t *ev)
{
    signal(SIGPIPE, SIG_IGN);
    struct sockaddr_in addr;
    int val, fd;
    char *ip = gInnerIP;
    mln_u16_t port = gInnerPort;

    /*accept*/
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);
    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        mln_log(error, "socket error. %s\n", strerror(errno));
        abort();
    }
    val = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) < 0) {
        mln_log(error, "setsockopt error. %s\n", strerror(errno));
        abort();
    }
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        mln_log(error, "bind error. %s\n", strerror(errno));
        abort();
    }
    if (listen(fd, 32767) < 0) {
        mln_log(error, "listen error. %s\n", strerror(errno));
        abort();
    }

    /*ev*/
    if (mln_event_set_fd(ev, \
                         fd, \
                         M_EV_RECV|M_EV_NONBLOCK, \
                         M_EV_UNLIMITED, \
                         NULL, \
                         portal_broadcaster_accept_handler) < 0)
    {
        mln_log(error, "No memory.\n");
        abort();
    }

    mln_event_dispatch(ev);
}

static void portal_broadcaster_accept_handler(mln_event_t *ev, int fd, void *data)
{
    char *ip;
    int connfd;
    socklen_t len;
    mln_u16_t port;
    struct sockaddr_in addr;
    portal_connection_t *conn;
    conn_type_t type = inner;
    mln_rbtree_node_t *rn;

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
        if ((conn = portal_connection_new(connfd, ip, port, type)) == NULL) {
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
                             portal_broadcaster_msg_recv_handler) < 0)
        {
            mln_log(error, "No memory.\n");
            mln_rbtree_delete(gInnerSet, rn);
            mln_rbtree_free_node(gInnerSet, rn);
            close(connfd);
            break;
        }
        if (gInnerTimeout >= 0) {
            mln_event_set_fd_timeout_handler(ev, connfd, conn, portal_broadcaster_close_handler);
        }

        mln_log(report, "%s %s:%u Connected.\n", type==inner?"Inner":"Outer", ip, port);
    }
}

static void portal_broadcaster_msg_recv_handler(mln_event_t *ev, int fd, void *data)
{
    int rc, err, ret;
    portal_message_t *msg;
    mln_chain_t *c;
    portal_connection_t *conn = (portal_connection_t *)data;
    mln_tcp_conn_t *tcpConn = portal_connection_getTcpConn(conn);

    rc = mln_tcp_conn_recv(tcpConn, M_C_TYPE_MEMORY);
    err = errno;
    c = mln_tcp_conn_remove(tcpConn, M_C_RECV);
again:
    msg = portal_connection_getMsg(conn);
    ret = portal_msg_chain2msg(&c, msg);
    if (ret == PORTAL_MSG_RET_OK) {
        if (msg->type == PORTAL_MSG_TYPE_HELLO || \
            msg->type == PORTAL_MSG_TYPE_ACK || \
            msg->type == PORTAL_MSG_TYPE_BYE || \
            msg->type == PORTAL_MSG_TYPE_ESTABLISH || \
            msg->type == PORTAL_MSG_TYPE_DATA)
        {
            struct broadcaster_toolset bt;
            bt.sender = conn;
            bt.msg = msg;
            bt.ev = ev;
            mln_rbtree_scan_all(gInnerSet, portal_broadcaster_broadcast, &bt);
        } else {
            mln_log(error, "Shouldn't be this type. %x\n", msg->type);
            if (c != NULL) mln_chain_pool_release_all(c);
            portal_broadcaster_close_handler(ev, fd, data);
            return;
        }
        portal_msg_init(portal_connection_getMsg(conn));
        goto again;
    } else if (ret == PORTAL_MSG_RET_ERROR) {
        if (c != NULL) mln_chain_pool_release_all(c);
        portal_broadcaster_close_handler(ev, fd, data);
        return;
    }
    /*PORTAL_MSG_RET_AGAIN*/
    if (c != NULL) {
        mln_tcp_conn_append_chain(tcpConn, c, NULL, M_C_RECV);
    }
    if (rc == M_C_ERROR) {
        mln_log(error, "recv error. %s\n", strerror(err));
        portal_broadcaster_close_handler(ev, fd, data);
        return;
    } else if (rc == M_C_CLOSED) {
        portal_broadcaster_close_handler(ev, fd, data);
        return;
    }
    if (mln_tcp_conn_get_head(tcpConn, M_C_SEND) == NULL) {
        mln_event_set_fd(ev, \
                         fd, \
                         M_EV_RECV|M_EV_NONBLOCK, \
                         gInnerTimeout, \
                         data, \
                         portal_broadcaster_msg_recv_handler);
        if (gInnerTimeout >= 0) {
            mln_event_set_fd_timeout_handler(ev, fd, data, portal_broadcaster_close_handler);
        }
    }
}

static void portal_broadcaster_close_handler(mln_event_t *ev, int fd, void *data)
{
    mln_rbtree_node_t *rn;
    portal_connection_t *conn = (portal_connection_t *)data;
    mln_event_set_fd(ev, fd, M_EV_CLR, M_EV_UNLIMITED, NULL, NULL);
    rn = mln_rbtree_search(gInnerSet, gInnerSet->root, conn);
    mln_rbtree_delete(gInnerSet, rn);
    mln_rbtree_free_node(gInnerSet, rn);
    close(fd);
}

static void portal_broadcaster_send_handler(mln_event_t *ev, int fd, void *data)
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
                             portal_broadcaster_send_handler);
        } else {
            mln_event_set_fd(ev, \
                             fd, \
                             M_EV_RECV|M_EV_NONBLOCK, \
                             gInnerTimeout, \
                             data, \
                             portal_broadcaster_msg_recv_handler);
            if (gInnerTimeout >= 0) {
                mln_event_set_fd_timeout_handler(ev, fd, data, portal_broadcaster_close_handler);
            }
        }
    } else if (rc == M_C_ERROR) {
        mln_log(error, "send error. %s\n", strerror(errno));
        portal_broadcaster_close_handler(ev, fd, data);
    } else {/*M_C_CLOSED*/
        portal_broadcaster_close_handler(ev, fd, data);
    }
}

static int portal_broadcaster_broadcast(mln_rbtree_node_t *node, void *rn_data, void *udata)
{
    mln_chain_t *c;
    portal_connection_t *conn = (portal_connection_t *)rn_data;
    mln_tcp_conn_t *tcpConn = portal_connection_getTcpConn(conn);
    struct broadcaster_toolset *bt = (struct broadcaster_toolset *)udata;

    if (conn == bt->sender) return 0;

    if ((c = portal_msg_msg2chain(portal_connection_getPool(conn), bt->msg)) == NULL) {
        mln_log(error, "No memory.\n");
        return 0;
    }
    mln_tcp_conn_append(tcpConn, c, M_C_SEND);
    mln_event_set_fd(bt->ev, \
                     mln_tcp_conn_get_fd(tcpConn), \
                     M_EV_SEND|M_EV_NONBLOCK|M_EV_APPEND|M_EV_ONESHOT, \
                     M_EV_UNLIMITED, \
                     conn, \
                     portal_broadcaster_send_handler);
    return 0;
}



