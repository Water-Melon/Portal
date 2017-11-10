/*
 * Copyright (C) Niklaus F.Schen.
 */
#ifndef __PORTAL_MESSAGE_H
#define __PORTAL_MESSAGE_H

#include "mln_chain.h"
#include "mln_alloc.h"
#include "portal.h"

#define PORTAL_MESSAGE_UNITLEN     1024
#define PORTAL_MSG_STAGE_SEQHIGH   0
#define PORTAL_MSG_STAGE_SEQLOW    1
#define PORTAL_MSG_STAGE_TYPE      2
#define PORTAL_MSG_STAGE_SERVERKEY 3
#define PORTAL_MSG_STAGE_CLIENTKEY 4
#define PORTAL_MSG_STAGE_LEN       5
#define PORTAL_MSG_STAGE_DATA      6
#define PORTAL_MSG_TYPE_HELLO      0
#define PORTAL_MSG_TYPE_ACK        1
#define PORTAL_MSG_TYPE_BYE        2
#define PORTAL_MSG_TYPE_ESTABLISH  3
#define PORTAL_MSG_TYPE_DATA       4

#define PORTAL_MSG_RET_OK          0
#define PORTAL_MSG_RET_AGAIN       1
#define PORTAL_MSG_RET_ERROR       2

typedef struct portal_message_s {
    mln_u32_t                stage;
    mln_u64_t                seqHigh;
    mln_u64_t                seqLow;
    mln_u32_t                type;
    mln_u32_t                len;
    mln_u32_t                left;
    mln_u8_t                 serverKey[PORTAL_KEY_LEN];
    mln_u8_t                 clientKey[PORTAL_KEY_LEN];
    mln_u8_t                 buf[PORTAL_MESSAGE_UNITLEN];
    struct portal_message_s *prev;
    struct portal_message_s *next;
} portal_message_t;

#define portal_littleendian_decode(buf, len, var); \
{\
    mln_size_t i = 0;\
    mln_u8ptr_t ptr = (mln_u8ptr_t)(buf);\
    for ((var) = 0; i < (len); ++i) {\
        (var) |= ((((mln_u64_t)(*ptr++)) & 0xff) << (i << 3));\
    }\
    (buf) = ptr;\
}

#define portal_littleendian_encode(buf, len, var); \
{\
    mln_size_t i = 0;\
    mln_u8ptr_t ptr = (mln_u8ptr_t)(buf);\
    for (; i < (len); ++i) {\
        *ptr++ = ((var) >> (i << 3)) & 0xff;\
    }\
    (buf) = ptr;\
}

#define portal_msg_init(pmsg) \
    ((pmsg)->stage = PORTAL_MSG_STAGE_SEQHIGH, \
     (pmsg)->seqHigh = 0, \
     (pmsg)->seqLow = 0, \
     (pmsg)->type = PORTAL_MSG_TYPE_DATA, \
     (pmsg)->len = 0, \
     (pmsg)->left = sizeof((pmsg)->seqHigh), \
     (pmsg)->serverKey[0] = 0, \
     (pmsg)->clientKey[0] = 0, \
     (pmsg)->buf[0] = 0, \
     (pmsg)->prev = NULL, \
     (pmsg)->next = NULL)

extern portal_message_t *portal_message_dup(portal_message_t *src) __NONNULL1(1);
extern void portal_message_free(portal_message_t *msg);
extern int portal_msg_chain2msg(mln_chain_t **c, portal_message_t *msg) __NONNULL2(1,2);
extern mln_chain_t *portal_msg_msg2chain(mln_alloc_t *pool, portal_message_t *msg) __NONNULL2(1,2);
extern int portal_msg_getBytes(mln_chain_t **c, void *buffer, mln_u32_t *left) __NONNULL3(1,2,3);
extern mln_chain_t *portal_msg_extractFromMsg(mln_alloc_t *pool, portal_message_t *msg) __NONNULL2(1,2);
extern portal_message_t *portal_msg_packUpMsg(portal_message_t *msg, \
                                              mln_chain_t **c, \
                                              mln_u8ptr_t serverKey, \
                                              mln_u8ptr_t clientKey, \
                                              mln_u32_t type, \
                                              mln_u64_t sndSeqHigh, \
                                              mln_u64_t sndSeqLow) __NONNULL1(1);
#endif



