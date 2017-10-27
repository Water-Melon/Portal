/*
 * Copyright (C) Niklaus F.Schen.
 */
#ifndef __PORTAL_CONNECTION_H
#define __PORTAL_CONNECTION_H

#include "mln_connection.h"
#include "mln_sha.h"
#include "message.h"
#include "mln_event.h"

#define __CONNECTION_IP_LEN  64

typedef struct portal_channel_s portal_channel_t;

typedef enum {
    outer = 0,
    inner
} conn_type_t;

typedef struct portal_connection_s {
    conn_type_t                 type;
    mln_u8_t                    localKey[__M_SHA_BUFLEN];
    mln_u8_t                    remoteKey[__M_SHA_BUFLEN];
    mln_tcp_conn_t              conn;
    portal_message_t            msg;
    mln_alloc_t                *pool;
    portal_message_t           *msgHead;
    portal_message_t           *msgTail;
    mln_u64_t                   sndSeqHigh;
    mln_u64_t                   sndSeqLow;
    mln_u64_t                   rcvSeqHigh;
    mln_u64_t                   rcvSeqLow;
    mln_u64_t                   closeSeqHigh;
    mln_u64_t                   closeSeqLow;
    mln_s8_t                    ip[__CONNECTION_IP_LEN];
    mln_u16_t                   port;
    mln_u32_t                   close:1;
    struct portal_connection_s *prev;
    struct portal_connection_s *next;
    portal_channel_t           *channel;
} portal_connection_t;

struct portal_channel_s {
    portal_connection_t        *accept;
    portal_connection_t        *connect;
};

#define portal_connection_shouldClose(pconn)   \
((pconn)->close == 1 && \
(pconn)->closeSeqHigh == (pconn)->rcvSeqHigh && \
(pconn)->closeSeqLow == (pconn)->rcvSeqLow)
#define portal_connection_setClose(pconn,seqHigh, seqLow) \
((pconn)->close = 1, (pconn)->closeSeqHigh = (seqHigh), (pconn)->closeSeqLow = (seqLow))
#define portal_connection_getType(pconn)                  ((pconn)->type)
#define portal_connection_getLocalKey(pconn)              ((pconn)->localKey)
#define portal_connection_getRemoteKey(pconn)             ((pconn)->remoteKey)
#define portal_connection_getMsg(pconn)                   (&((pconn)->msg))
#define portal_connection_getPool(pconn)                  ((pconn)->pool)
#define portal_connection_getTcpConn(pconn)               (&((pconn)->conn))
#define portal_connection_getChannel(pconn)               ((pconn)->channel)

#define portal_channel_setAccept(channel,conn)            ((channel)->accept = (conn))
#define portal_channel_setConnect(channel,conn)           ((channel)->connect = (conn))

extern portal_connection_t *portal_connection_new(int sockfd, char *ip, mln_u16_t port, conn_type_t type) __NONNULL1(2);
extern void portal_connection_free(portal_connection_t *conn);
extern int portal_connection_cmp(const portal_connection_t *conn1, const portal_connection_t *conn2) __NONNULL2(1,2);
extern portal_connection_t *portal_connection_getInnerConn(void);
extern void portal_connection_moveChain(mln_event_t *ev, portal_connection_t *src, ev_fd_handler recv, ev_fd_handler send) __NONNULL3(1,3,4);
extern int portal_connection_addMsgBuildChain(portal_connection_t *conn, portal_message_t *msg, mln_chain_t **out) __NONNULL3(1,2,3);
extern portal_channel_t *portal_channel_new(void);
extern void portal_channel_free(portal_channel_t *ch);
#endif



