/*
 * Copyright (C) Niklaus F.Schen.
 */

#include "proxy.h"
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

static void portal_proxy_accept_handler(mln_event_t *ev, int fd, void *data);
static void portal_proxy_close_handler(mln_event_t *ev, int fd, void *data);
static int portal_proxy_connect(mln_event_t *ev, portal_channel_t *ch);
static void portal_proxy_connect_test(mln_event_t *ev, int fd, void *data);
static void portal_proxy_raw_recv_handler(mln_event_t *ev, int fd, void *data);
static void portal_proxy_msg_recv_handler(mln_event_t *ev, int fd, void *data);
static void portal_proxy_send_handler(mln_event_t *ev, int fd, void *data);

void portal_proxy_entrance(mln_event_t *ev)
{
    signal(SIGPIPE, SIG_IGN);
    struct sockaddr_in addr;
    int val, fd;
    char *ip = gIsServer? gInnerIP: gOuterIP;
    mln_u16_t port = gIsServer? gInnerPort: gOuterPort;

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
                         portal_proxy_accept_handler) < 0)
    {
        mln_log(error, "No memory.\n");
        abort();
    }

    mln_event_dispatch(ev);
}

static void portal_proxy_accept_handler(mln_event_t *ev, int fd, void *data)
{
    char *ip;
    int connfd;
    socklen_t len;
    mln_u16_t port;
    portal_channel_t *ch;
    struct sockaddr_in addr;
    portal_connection_t *conn;
    conn_type_t type = gIsServer? inner: outer;
    ev_fd_handler handler = gIsServer? portal_proxy_msg_recv_handler: portal_proxy_raw_recv_handler;

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
        if (mln_event_set_fd(ev, \
                             connfd, \
                             M_EV_RECV|M_EV_NONBLOCK|M_EV_ONESHOT, \
                             M_EV_UNLIMITED, \
                             conn, \
                             handler) < 0)
        {
            mln_log(error, "No memory.\n");
            portal_connection_free(conn);
            close(connfd);
            break;
        }

        if ((ch = portal_channel_new()) == NULL) {
            mln_log(error, "No memory.\n");
            portal_proxy_close_handler(ev, connfd, conn);
            break;
        }
        portal_channel_setAccept(ch, conn);
        portal_connection_setChannel(conn, ch);

        if (portal_proxy_connect(ev, ch) < 0) {
            portal_proxy_close_handler(ev, connfd, conn);
            continue;
        }
        mln_log(report, "%s %s:%u Connected.\n", type==inner?"Inner":"Outer", ip, port);
    }
}

static int portal_proxy_connect(mln_event_t *ev, portal_channel_t *ch)
{
    int sockfd, flg;
    struct sockaddr_in addr;
    char *ip = gIsServer? gOuterIP: gInnerIP;
    mln_u16_t port = gIsServer? gOuterPort: gInnerPort;

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        mln_log(error, "socket error. %s\n", strerror(errno));
        return -1;
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
        return -1;
    }
    if (mln_event_set_fd(ev, \
                         sockfd, \
                         M_EV_SEND|M_EV_NONBLOCK|M_EV_ONESHOT, \
                         M_EV_UNLIMITED, \
                         ch, \
                         portal_proxy_connect_test) < 0)
    {
        mln_log(error, "No memory.\n");
        close(sockfd);
        return -1;
    }
    return 0;
}

static void portal_proxy_connect_test(mln_event_t *ev, int fd, void *data)
{
    int err = 0;
    char *ip = gIsServer? gOuterIP: gInnerIP;
    ev_fd_handler handler = gIsServer? portal_proxy_raw_recv_handler: portal_proxy_msg_recv_handler;
    mln_u16_t port = gIsServer? gOuterPort: gInnerPort;
    portal_channel_t *ch = (portal_channel_t *)data;
    int acceptFd = mln_tcp_conn_get_fd(portal_connection_getTcpConn(ch->accept));
    conn_type_t type = gIsServer? outer: inner;
    socklen_t len = sizeof(err);
    portal_connection_t *conn;

    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0) {
        mln_log(error, "getsockopt error. %s\n", strerror(errno));
        mln_event_set_fd(ev, fd, M_EV_CLR, M_EV_UNLIMITED, NULL, NULL);
        close(fd);
        portal_proxy_close_handler(ev, acceptFd, ch->accept);
        return;
    }
    if (err) {
        if (err != EINPROGRESS) {
            mln_log(error, "connect error. %s\n", strerror(err));
            mln_event_set_fd(ev, fd, M_EV_CLR, M_EV_UNLIMITED, NULL, NULL);
            close(fd);
            portal_proxy_close_handler(ev, acceptFd, ch->accept);
            return;
        }
        mln_event_set_fd(ev, \
                         fd, \
                         M_EV_SEND|M_EV_NONBLOCK|M_EV_ONESHOT, \
                         M_EV_UNLIMITED, \
                         data, \
                         portal_proxy_connect_test);
        return;
    }

    if ((conn = portal_connection_new(fd, ip, port, type)) == NULL) {
        mln_log(error, "No memory or hash key conflict.\n");
        mln_event_set_fd(ev, fd, M_EV_CLR, M_EV_UNLIMITED, NULL, NULL);
        close(fd);
        portal_proxy_close_handler(ev, acceptFd, ch->accept);
        return;
    }
    portal_channel_setConnect(ch, conn);
    portal_connection_setChannel(conn, ch);
    mln_event_set_fd(ev, \
                     fd, \
                     M_EV_RECV|M_EV_NONBLOCK, \
                     gIsServer? gOuterTimeout: gInnerTimeout, \
                     conn, \
                     handler);
    mln_event_set_fd_timeout_handler(ev, fd, conn, portal_proxy_close_handler);
    handler = gIsServer? portal_proxy_msg_recv_handler: portal_proxy_raw_recv_handler;
    mln_event_set_fd(ev, \
                     acceptFd, \
                     M_EV_RECV|M_EV_NONBLOCK, \
                     gIsServer? gInnerTimeout: gOuterTimeout, \
                     ch->accept, \
                     handler);
    mln_event_set_fd_timeout_handler(ev, acceptFd, ch->accept, portal_proxy_close_handler);
}

static void portal_proxy_raw_recv_handler(mln_event_t *ev, int fd, void *data)
{
    int rc, err;
    portal_message_t *msg;
    mln_chain_t *c, *trans;
    portal_connection_t *conn = (portal_connection_t *)data;
    mln_tcp_conn_t *tcpConn = portal_connection_getTcpConn(conn);
    portal_connection_t *peerConn = gIsServer? conn->channel->accept: conn->channel->connect;
    mln_tcp_conn_t *peerTcpConn;

    if (peerConn == NULL) return;
    peerTcpConn = portal_connection_getTcpConn(peerConn);

    rc = mln_tcp_conn_recv(tcpConn, M_C_TYPE_MEMORY);
    err = errno;
    c = mln_tcp_conn_remove(tcpConn, M_C_RECV);
    while (c != NULL) {
        msg = portal_msg_packUpMsg(portal_connection_getMsg(conn), \
                                   &c, \
                                   portal_connection_getLocalKey(conn), \
                                   portal_connection_getRemoteKey(conn), \
                                   PORTAL_MSG_TYPE_DATA, \
                                   0, 0);
        if ((trans = portal_msg_msg2chain(portal_connection_getPool(peerConn), msg)) == NULL) {
            mln_log(error, "No memory.\n");
            if (c != NULL) mln_chain_pool_release_all(c);
            portal_proxy_close_handler(ev, fd, data);
            return;
        }
        mln_tcp_conn_append(peerTcpConn, trans, M_C_SEND);
        mln_event_set_fd(ev, \
                         mln_tcp_conn_get_fd(peerTcpConn), \
                         M_EV_SEND|M_EV_NONBLOCK|M_EV_APPEND|M_EV_ONESHOT, \
                         M_EV_UNLIMITED, \
                         peerConn, \
                         portal_proxy_send_handler);
    }
    if (rc == M_C_ERROR) {
        if (err != ECONNRESET) {
            mln_log(error, "recv error. %s\n", strerror(err));
        }
        portal_proxy_close_handler(ev, fd, data);
    } else if (rc == M_C_CLOSED) {
        portal_proxy_close_handler(ev, fd, data);
    }
}

static void portal_proxy_msg_recv_handler(mln_event_t *ev, int fd, void *data)
{
    int rc, err, ret;
    portal_message_t *msg;
    mln_chain_t *c, *trans;
    portal_connection_t *conn = (portal_connection_t *)data;
    mln_tcp_conn_t *tcpConn = portal_connection_getTcpConn(conn);
    portal_connection_t *peerConn = gIsServer? conn->channel->connect: conn->channel->accept;
    mln_tcp_conn_t *peerTcpConn;

    if (peerConn == NULL) return;
    peerTcpConn = portal_connection_getTcpConn(peerConn);

    rc = mln_tcp_conn_recv(tcpConn, M_C_TYPE_MEMORY);
    err = errno;
    c = mln_tcp_conn_remove(tcpConn, M_C_RECV);
again:
    msg = portal_connection_getMsg(conn);
    ret = portal_msg_chain2msg(&c, msg);
    if (ret == PORTAL_MSG_RET_OK) {
        if (msg->type == PORTAL_MSG_TYPE_DATA) {
            if ((trans = portal_msg_extractFromMsg(mln_tcp_conn_get_pool(peerConn), msg)) == NULL) {
                if (c != NULL) mln_chain_pool_release_all(c);
                portal_proxy_close_handler(ev, fd, data);
                return;
            }
            mln_tcp_conn_append(peerTcpConn, trans, M_C_SEND);
            mln_event_set_fd(ev, \
                             mln_tcp_conn_get_fd(peerTcpConn), \
                             M_EV_SEND|M_EV_NONBLOCK|M_EV_APPEND|M_EV_ONESHOT, \
                             M_EV_UNLIMITED, \
                             peerConn, \
                             portal_proxy_send_handler);
        } else {
            mln_log(error, "Shouldn't be this type. %x\n", msg->type);
            if (c != NULL) mln_chain_pool_release_all(c);
            portal_proxy_close_handler(ev, fd, data);
            return;
        }
        portal_msg_init(portal_connection_getMsg(conn));
        goto again;
    } else if (ret == PORTAL_MSG_RET_ERROR) {
        if (c != NULL) mln_chain_pool_release_all(c);
        portal_proxy_close_handler(ev, fd, data);
        return;
    }
    /*PORTAL_MSG_RET_AGAIN*/
    if (c != NULL) {
        mln_tcp_conn_append_chain(tcpConn, c, NULL, M_C_RECV);
    }
    if (rc == M_C_ERROR) {
        mln_log(error, "recv error. %s\n", strerror(err));
        portal_proxy_close_handler(ev, fd, data);
    } else if (rc == M_C_CLOSED) {
        portal_proxy_close_handler(ev, fd, data);
    }
}

static void portal_proxy_close_handler(mln_event_t *ev, int fd, void *data)
{
    portal_connection_t *conn = (portal_connection_t *)data;
    portal_connection_t *peerConn = conn==conn->channel->accept? \
                                        conn->channel->connect: \
                                        conn->channel->accept;

    mln_event_set_fd(ev, fd, M_EV_CLR, M_EV_UNLIMITED, NULL, NULL);
    portal_connection_free(conn);
    close(fd);
    if (peerConn != NULL) {
        mln_tcp_conn_t *peerTcpConn = portal_connection_getTcpConn(peerConn);
        if (mln_tcp_conn_get_head(peerTcpConn, M_C_SEND) == NULL) {
            portal_proxy_close_handler(ev, mln_tcp_conn_get_fd(peerTcpConn), peerConn);
        } else {
            portal_connection_setClose(peerConn, 0, 0);
            shutdown(mln_tcp_conn_get_fd(peerTcpConn), SHUT_RD);
            mln_event_set_fd(ev, \
                             mln_tcp_conn_get_fd(peerTcpConn), \
                             M_EV_SEND|M_EV_NONBLOCK|M_EV_ONESHOT, \
                             M_EV_UNLIMITED, \
                             peerConn, \
                             portal_proxy_send_handler);
        }
    }
}

static void portal_proxy_send_handler(mln_event_t *ev, int fd, void *data)
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
                             portal_proxy_send_handler);
        } else {
            if (conn->close) {
                portal_proxy_close_handler(ev, fd, data);
                return;
            }
            ev_fd_handler handler;
            int timeout;
            if (gIsServer) {
                if (conn == conn->channel->accept) {
                    handler = portal_proxy_msg_recv_handler;
                    timeout = gInnerTimeout;
                } else {
                    handler = portal_proxy_raw_recv_handler;
                    timeout = gOuterTimeout;
                }
            } else {
                if (conn == conn->channel->accept) {
                    handler = portal_proxy_raw_recv_handler;
                    timeout = gOuterTimeout;
                } else {
                    handler = portal_proxy_msg_recv_handler;
                    timeout = gInnerTimeout;
                }
            }
            mln_event_set_fd(ev, \
                             fd, \
                             M_EV_RECV|M_EV_NONBLOCK, \
                             timeout, \
                             data, \
                             handler);
            mln_event_set_fd_timeout_handler(ev, fd, data, portal_proxy_close_handler);
        }
    } else if (rc == M_C_ERROR) {
        mln_log(error, "send error. %s\n", strerror(errno));
        portal_proxy_close_handler(ev, fd, data);
    } else {/*M_C_CLOSED*/
        portal_proxy_close_handler(ev, fd, data);
    }
}



