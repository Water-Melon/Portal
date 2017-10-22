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
    mln_u64_t                   sndSeq;
    mln_u64_t                   rcvSeq;
    mln_u64_t                   closeSeq;
    mln_s8_t                    ip[__CONNECTION_IP_LEN];
    mln_u16_t                   port;
    mln_u32_t                   close:1;
    struct portal_connection_s *prev;
    struct portal_connection_s *next;
} portal_connection_t;

#define portal_connection_shouldClose(pconn)   ((pconn)->close == 1 && (pconn)->closeSeq == (pconn)->rcvSeq)
#define portal_connection_setClose(pconn,seq)  ((pconn)->close = 1, (pconn)->closeSeq = (seq))
#define portal_connection_getType(pconn)       ((pconn)->type)
#define portal_connection_getLocalKey(pconn)   ((pconn)->localKey)
#define portal_connection_getRemoteKey(pconn)  ((pconn)->remoteKey)
#define portal_connection_getMsg(pconn)        (&((pconn)->msg))
#define portal_connection_getPool(pconn)       ((pconn)->pool)
#define portal_connection_getTcpConn(pconn)    (&((pconn)->conn))

extern portal_connection_t *portal_connection_new(int sockfd, char *ip, mln_u16_t port, conn_type_t type) __NONNULL1(2);
extern void portal_connection_free(portal_connection_t *conn);
extern int portal_connection_cmp(const portal_connection_t *conn1, const portal_connection_t *conn2) __NONNULL2(1,2);
extern portal_connection_t *portal_connection_getInnerConn(void);
extern void portal_connection_moveChain(mln_event_t *ev, portal_connection_t *src, ev_fd_handler recv, ev_fd_handler send) __NONNULL3(1,3,4);
extern int portal_connection_addMsgBuildChain(portal_connection_t *conn, portal_message_t *msg, mln_chain_t **out) __NONNULL3(1,2,3);
#endif



