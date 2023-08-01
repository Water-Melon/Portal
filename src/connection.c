/*
 * Copyright (C) Niklaus F.Schen.
 */

#include "connection.h"
#include "mln_alloc.h"
#include "mln_log.h"
#include <stdlib.h>
#include <sys/time.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

static mln_u64_t nConn = 0;
static portal_connection_t *connHead = NULL;
static portal_connection_t *connTail = NULL;
static portal_connection_t *connCur = NULL;

MLN_CHAIN_FUNC_DECLARE(portal_connection, \
                       portal_connection_t, \
                       static inline void, \
                       __NONNULL3(1,2,3));
MLN_CHAIN_FUNC_DECLARE(portal_message, \
                       portal_message_t, \
                       static inline void, \
                       __NONNULL3(1,2,3));

portal_channel_t *portal_channel_new(void)
{
    portal_channel_t *ch;
    if ((ch = (portal_channel_t *)malloc(sizeof(portal_channel_t))) == NULL) {
        return NULL;
    }
    ch->accept = NULL;
    ch->connect = NULL;
    return ch;
}

void portal_channel_free(portal_channel_t *ch)
{
    if (ch == NULL) return;
    free(ch);
}

portal_connection_t *portal_connection_new(int sockfd, char *ip, mln_u16_t port, conn_type_t type)
{
    mln_sha256_t sha;
    mln_u8_t hashbuf[32] = {0};
    portal_connection_t *conn;
    struct timeval now;
    mln_u64_t time;
    mln_size_t len = strlen(ip);;

    if ((conn = (portal_connection_t *)malloc(sizeof(portal_connection_t))) == NULL) {
        return NULL;
    }
    conn->type = type;
    mln_sha256_init(&sha);
    gettimeofday(&now, NULL);
    time = now.tv_sec * 1000000 + now.tv_usec;
    memcpy(hashbuf, &sockfd, 4);
    memcpy(hashbuf+4, &port, 2);
    memcpy(hashbuf+6, &time, 8);
    memcpy(hashbuf+14, ip, len);
    mln_sha256_calc(&sha, hashbuf, 14+len, 1);
    mln_sha256_tobytes(&sha, (mln_u8ptr_t)(conn->localKey), PORTAL_KEY_LEN);
    conn->remoteKey[0] = 0;
    if (mln_tcp_conn_init(&(conn->conn), sockfd)) {
        free(conn);
        return NULL;
    }
    portal_msg_init(&(conn->msg));
    conn->pool = mln_tcp_conn_pool_get(&(conn->conn));
    conn->msgTail = conn->msgHead = NULL;
    conn->sndSeqHigh = 0;
    conn->sndSeqLow = 0;
    conn->rcvSeqHigh = 0;
    conn->rcvSeqLow = 0;
    conn->closeSeqHigh = 0;
    conn->closeSeqLow = 0;
    len = len >= __CONNECTION_IP_LEN? __CONNECTION_IP_LEN-1: len;
    memcpy(conn->ip, ip, len);
    conn->ip[len] = 0;
    conn->port = port;
    conn->close = 0;
    conn->prev = NULL;
    conn->next = NULL;
    conn->channel = NULL;

    if (type == inner) {
        portal_connection_chain_add(&connHead, &connTail, conn);
        if (connCur == NULL) connCur = conn;
        ++nConn;
    }

    return conn;
}

void portal_connection_free(portal_connection_t *conn)
{
    portal_message_t *fr;
    if (conn == NULL) return;
    if (conn->type == inner) {
        --nConn;
        if (connCur == conn) {
            if (conn == connHead) {
                if (conn == connTail) {
                    connCur = NULL;
                } else {
                    connCur = connCur->next;
                }
            } else {
                if (conn == connTail) {
                    connCur = connHead;
                } else {
                    connCur = connCur->next;
                }
            }
        }
        portal_connection_chain_del(&connHead, &connTail, conn);
    }
    while ((fr = conn->msgHead) != NULL) {
        portal_message_chain_del(&(conn->msgHead), &(conn->msgTail), fr);
        portal_message_free(fr);
    }
    mln_tcp_conn_destroy(&(conn->conn));
    if (conn->channel != NULL) {
        if (conn->channel->accept == conn) {
            conn->channel->accept = NULL;
            if (conn->channel->connect == NULL) {
                portal_channel_free(conn->channel);
            }
        } else {
            conn->channel->connect = NULL;
            if (conn->channel->accept == NULL) {
                portal_channel_free(conn->channel);
            }
        }
    }
    free(conn);
}

int portal_connection_cmp(const portal_connection_t *conn1, const portal_connection_t *conn2)
{
    return memcmp(conn1->localKey, conn2->localKey, PORTAL_KEY_LEN);
}

portal_connection_t *portal_connection_getInnerConn(void)
{
    if (connCur == NULL) return NULL;
    portal_connection_t *ret = connCur;
    connCur = connCur->next;
    if (connCur == NULL) connCur = connHead;
    return ret;
}

void portal_connection_moveChain(mln_event_t *ev, portal_connection_t *src, ev_fd_handler recv, ev_fd_handler send)
{
    if (src == NULL) return;
    portal_connection_t *dest = portal_connection_getInnerConn();
    if (dest == NULL) return;
    if (dest == src) dest = portal_connection_getInnerConn();
    if (dest == NULL || dest == src) return;

    mln_u8ptr_t buf;
    mln_buf_t *b;
    mln_u64_t size;
    mln_chain_t *rcvHead = NULL, *rcvTail = NULL;
    mln_chain_t *sndHead = NULL, *sndTail = NULL;
    mln_chain_t *sntHead = NULL, *sntTail = NULL;
    mln_chain_t *c, *move;
    mln_tcp_conn_t *srcTcpConn = &(src->conn), *destTcpConn = &(dest->conn);
    mln_alloc_t *pool = mln_tcp_conn_pool_get(destTcpConn);

    c = mln_tcp_conn_head(srcTcpConn, M_C_RECV);
    for (; c != NULL; c = c->next) {
        if (c->buf != NULL && (size = mln_buf_left_size(c->buf))) {
            buf = (mln_u8ptr_t)mln_alloc_m(pool, size);
            if (buf == NULL) goto err;
            memcpy(buf, c->buf->left_pos, size);
            if ((b = mln_buf_new(pool)) == NULL) {
                mln_alloc_free(buf);
                goto err;
            }
            b->left_pos = b->pos = b->start = buf;
            b->last = b->end = buf + size;
            b->in_memory = 1;
            b->last_buf = 1;
            if ((move = mln_chain_new(pool)) == NULL) {
                mln_buf_pool_release(b);
                goto err;
            }
            move->buf = b;
            if (rcvHead == NULL) {
                rcvHead = rcvTail = move;
            } else {
                rcvTail->next = move;
                rcvTail = move;
            }
        }
    }

    c = mln_tcp_conn_head(srcTcpConn, M_C_SEND);
    for (; c != NULL; c = c->next) {
        if (c->buf != NULL && (size = mln_buf_left_size(c->buf))) {
            buf = (mln_u8ptr_t)mln_alloc_m(pool, size);
            if (buf == NULL) goto err;
            memcpy(buf, c->buf->left_pos, size);
            if ((b = mln_buf_new(pool)) == NULL) {
                mln_alloc_free(buf);
                goto err;
            }
            b->left_pos = b->pos = b->start = buf;
            b->last = b->end = buf + size;
            b->in_memory = 1;
            b->last_buf = 1;
            if ((move = mln_chain_new(pool)) == NULL) {
                mln_buf_pool_release(b);
                goto err;
            }
            move->buf = b;
            if (sndHead == NULL) {
                sndHead = sndTail = move;
            } else {
                sndTail->next = move;
                sndTail = move;
            }
        }
    }

    c = mln_tcp_conn_head(srcTcpConn, M_C_SENT);
    for (; c != NULL; c = c->next) {
        if (c->buf != NULL && (size = mln_buf_left_size(c->buf))) {
            buf = (mln_u8ptr_t)mln_alloc_m(pool, size);
            if (buf == NULL) goto err;
            memcpy(buf, c->buf->left_pos, size);
            if ((b = mln_buf_new(pool)) == NULL) {
                mln_alloc_free(buf);
                goto err;
            }
            b->left_pos = b->pos = b->start = buf;
            b->last = b->end = buf + size;
            b->in_memory = 1;
            b->last_buf = 1;
            if ((move = mln_chain_new(pool)) == NULL) {
                mln_buf_pool_release(b);
                goto err;
            }
            move->buf = b;
            if (sntHead == NULL) {
                sntHead = sntTail = move;
            } else {
                sntTail->next = move;
                sntTail = move;
            }
        }
    }

    if (rcvHead != NULL) {
        mln_tcp_conn_append_chain(destTcpConn, rcvHead, rcvTail, M_C_RECV);
        recv(ev, mln_tcp_conn_fd_get(destTcpConn), dest);
    }
    if (sntHead != NULL) {
        mln_tcp_conn_append_chain(destTcpConn, sntHead, sntTail, M_C_SEND);
        send(ev, mln_tcp_conn_fd_get(destTcpConn), dest);
    }
    if (sndHead != NULL) {
        mln_tcp_conn_append_chain(destTcpConn, sndHead, sndTail, M_C_SEND);
        send(ev, mln_tcp_conn_fd_get(destTcpConn), dest);
    }
    return;
err:
    if (rcvHead != NULL) mln_chain_pool_release_all(rcvHead);
    if (sndHead != NULL) mln_chain_pool_release_all(sndHead);
    if (sntHead != NULL) mln_chain_pool_release_all(sntHead);
}

int portal_connection_addMsgBuildChain(portal_connection_t *conn, portal_message_t *msg, mln_chain_t **out)
{
    mln_chain_t *c_head = NULL, *c_tail = NULL, *c;
    mln_tcp_conn_t *tcpConn = portal_connection_getTcpConn(conn);
    portal_message_t *scan = conn->msgHead;

    if ((msg->seqHigh < conn->rcvSeqHigh) || \
        (msg->seqHigh == conn->rcvSeqHigh && msg->seqLow < conn->rcvSeqLow))
    {
        portal_message_free(msg);
	*out = NULL;
        return 0;
    }

    for (; scan != NULL; scan = scan->next) {
        if ((scan->seqHigh > msg->seqHigh) || \
            (scan->seqHigh == msg->seqHigh && scan->seqLow >= msg->seqLow))
        {
            if (scan->seqHigh == msg->seqHigh && scan->seqLow == msg->seqLow) {
                portal_message_free(msg);
	        *out = NULL;
                return 0;
            }
            break;
        }
    }
    if (scan == NULL) {
        portal_message_chain_add(&(conn->msgHead), &(conn->msgTail), msg);
    } else {
        if (scan->seqHigh == msg->seqHigh && scan->seqLow == msg->seqLow) {
            mln_log(error, "Invalid message.\n");
            portal_message_free(msg);
            return -1;
        }
        if (scan == conn->msgHead) {
            msg->prev = NULL;
            scan->prev = msg;
            msg->next = scan;
            conn->msgHead = msg;
        } else {
            scan->prev->next = msg;
            msg->prev = scan->prev;
            msg->next = scan;
            scan->prev = msg;
        }
    }

    while ((scan = conn->msgHead) != NULL) {
        if (scan->seqHigh != conn->rcvSeqHigh || scan->seqLow != conn->rcvSeqLow) {
            break;
        }
        c = portal_msg_extractFromMsg(mln_tcp_conn_pool_get(tcpConn), scan);
        if (c == NULL) {
            if (c_head != NULL) mln_chain_pool_release_all(c_head);
            return -1;
        }
        if (c_head == NULL) {
            c_head = c_tail = c;
        } else {
            c_tail->next = c;
            c_tail = c;
        }
        portal_message_chain_del(&(conn->msgHead), &(conn->msgTail), scan);
        portal_message_free(scan);
        if (++conn->rcvSeqLow == 0) ++conn->rcvSeqHigh;
    }
    *out = c_head;

    return 0;
}

MLN_CHAIN_FUNC_DEFINE(portal_connection, \
                      portal_connection_t, \
                      static inline void, \
                      prev, \
                      next);
MLN_CHAIN_FUNC_DEFINE(portal_message, \
                      portal_message_t, \
                      static inline void, \
                      prev, \
                      next);



