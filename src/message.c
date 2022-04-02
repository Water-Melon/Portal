/*
 * Copyright (C) Niklaus F.Schen.
 */

#include "message.h"
#include <sys/time.h>
#include "mln_log.h"
#include <stdlib.h>
#include "mln_rc.h"
#include "mln_global.h"

portal_message_t *portal_message_dup(portal_message_t *src)
{
    portal_message_t *ret = (portal_message_t *)malloc(sizeof(portal_message_t));
    if (ret == NULL) return NULL;
    memcpy(ret, src, sizeof(portal_message_t));
    return ret;
}

void portal_message_free(portal_message_t *msg)
{
    if (msg == NULL) return;
    free(msg);
}

static inline int
__portal_msg_getBytes(mln_chain_t **c, void *buffer, mln_u32_t *left)
{
    mln_size_t _left = *left, len = 0;
    mln_chain_t *fr;
    mln_u8ptr_t buf = (mln_u8ptr_t)buffer;

    while (*c != NULL) {
        if ((*c)->buf == NULL || !(len = mln_buf_left_size((*c)->buf))) {
            fr = *c;
            *c = (*c)->next;
            mln_chain_pool_release(fr);
            continue;
        }
        if (!_left) break;
        if (len > _left) {
            memcpy(buf, (*c)->buf->left_pos, _left);
            (*c)->buf->left_pos += _left;
            _left = 0;
        } else {
            memcpy(buf, (*c)->buf->left_pos, len);
            (*c)->buf->left_pos += len;
            buf += len;
            _left -= len;
        }
    }
    *left = _left;
    return _left? PORTAL_MSG_RET_AGAIN: PORTAL_MSG_RET_OK;
}

int portal_msg_getBytes(mln_chain_t **c, void *buffer, mln_u32_t *left)
{
    return __portal_msg_getBytes(c, buffer, left);
}

int portal_msg_chain2msg(mln_chain_t **c, portal_message_t *msg)
{
    int rc = PORTAL_MSG_RET_OK;
    mln_u8ptr_t tmp;
    mln_u32_t data, wrt = 0;
    mln_u64_t tmpseq;

    switch (msg->stage) {
        case PORTAL_MSG_STAGE_SEQHIGH:
            wrt = sizeof(msg->seqHigh) - msg->left;
            rc = __portal_msg_getBytes(c, (mln_u8ptr_t)(&(msg->seqHigh))+wrt, &(msg->left));
            if (rc != PORTAL_MSG_RET_OK) {
                if (rc == PORTAL_MSG_RET_ERROR)
                    portal_msg_init(msg);
                return rc;
            }
            tmpseq = msg->seqHigh;
            tmp = (mln_u8ptr_t)(&tmpseq);
            portal_littleendian_decode(tmp, sizeof(tmpseq), msg->seqHigh);
            msg->stage = PORTAL_MSG_STAGE_SEQLOW;
            msg->left = sizeof(msg->seqLow);
        case PORTAL_MSG_STAGE_SEQLOW:
            wrt = sizeof(msg->seqLow) - msg->left;
            rc = __portal_msg_getBytes(c, (mln_u8ptr_t)(&(msg->seqLow))+wrt, &(msg->left));
            if (rc != PORTAL_MSG_RET_OK) {
                if (rc == PORTAL_MSG_RET_ERROR)
                    portal_msg_init(msg);
                return rc;
            }
            tmpseq = msg->seqLow;
            tmp = (mln_u8ptr_t)(&tmpseq);
            portal_littleendian_decode(tmp, sizeof(tmpseq), msg->seqLow);
            msg->stage = PORTAL_MSG_STAGE_TYPE;
            msg->left = sizeof(msg->type);
        case PORTAL_MSG_STAGE_TYPE:
            wrt = sizeof(msg->type) - msg->left;
            rc = __portal_msg_getBytes(c, (mln_u8ptr_t)(&(msg->type))+wrt, &(msg->left));
            if (rc != PORTAL_MSG_RET_OK) {
                if (rc == PORTAL_MSG_RET_ERROR)
                    portal_msg_init(msg);
                return rc;
            }
            data = msg->type;
            tmp = (mln_u8ptr_t)(&data);
            portal_littleendian_decode(tmp, sizeof(data), msg->type);
            msg->stage = PORTAL_MSG_STAGE_SERVERKEY;
            msg->left = PORTAL_KEY_LEN;
        case PORTAL_MSG_STAGE_SERVERKEY:
            wrt = PORTAL_KEY_LEN - msg->left;
            rc = __portal_msg_getBytes(c, msg->serverKey+wrt, &(msg->left));
            if (rc != PORTAL_MSG_RET_OK) {
                if (rc == PORTAL_MSG_RET_ERROR)
                    portal_msg_init(msg);
                return rc;
            }
            msg->stage = PORTAL_MSG_STAGE_CLIENTKEY;
            msg->left = PORTAL_KEY_LEN;
        case PORTAL_MSG_STAGE_CLIENTKEY:
            wrt = PORTAL_KEY_LEN - msg->left;
            rc = __portal_msg_getBytes(c, msg->clientKey+wrt, &(msg->left));
            if (rc != PORTAL_MSG_RET_OK) {
                if (rc == PORTAL_MSG_RET_ERROR)
                    portal_msg_init(msg);
                return rc;
            }
            msg->stage = PORTAL_MSG_STAGE_LEN;
            msg->left = sizeof(msg->len);
        case PORTAL_MSG_STAGE_LEN:
            wrt = sizeof(mln_u32_t) - msg->left;
            rc = __portal_msg_getBytes(c, (mln_u8ptr_t)(&(msg->len))+wrt, &(msg->left));
            if (rc != PORTAL_MSG_RET_OK) {
                if (rc == PORTAL_MSG_RET_ERROR)
                    portal_msg_init(msg);
                return rc;
            }
            data = msg->len;
            tmp = (mln_u8ptr_t)(&data);
            portal_littleendian_decode(tmp, sizeof(data), msg->len);
            if (msg->len > PORTAL_MESSAGE_UNITLEN) {
                portal_msg_init(msg);
                return PORTAL_MSG_RET_ERROR;
            }
            msg->stage = PORTAL_MSG_STAGE_DATA;
            msg->left = msg->len;
            if (msg->len > PORTAL_MESSAGE_UNITLEN) {
                portal_msg_init(msg);
                return PORTAL_MSG_RET_ERROR;
            }
        case PORTAL_MSG_STAGE_DATA:
            wrt = msg->len - msg->left;
            rc = __portal_msg_getBytes(c, msg->buf+wrt, &(msg->left));
            if (rc != PORTAL_MSG_RET_OK) {
                if (rc == PORTAL_MSG_RET_ERROR)
                    portal_msg_init(msg);
                return rc;
            }
            msg->stage = PORTAL_MSG_STAGE_HASH;
            msg->left = PORTAL_KEY_LEN;
        default:
            wrt = PORTAL_KEY_LEN - msg->left;
            rc = __portal_msg_getBytes(c, msg->hash+wrt, &(msg->left));
            if (rc != PORTAL_MSG_RET_OK) {
                if (rc == PORTAL_MSG_RET_ERROR)
                    portal_msg_init(msg);
                return rc;
            }
            msg->stage = PORTAL_MSG_STAGE_SEQHIGH;
            msg->left = sizeof(msg->seqHigh);
            break;
    }
    return rc;
}

mln_chain_t *portal_msg_msg2chain(mln_alloc_t *pool, portal_message_t *msg)
{
    mln_chain_t *c;
    mln_buf_t *b;
    mln_u8ptr_t buf;
    mln_size_t blen;

    if ((c = mln_chain_new(pool)) == NULL) {
        return NULL;
    }
    if ((b = mln_buf_new(pool)) == NULL) {
        mln_chain_pool_release(c);
        return NULL;
    }
    c->buf = b;
    blen = sizeof(mln_u32_t)*2 + PORTAL_KEY_LEN*3 + msg->len + sizeof(mln_u64_t)*2;
    if ((buf = (mln_u8ptr_t)mln_alloc_m(pool, blen)) == NULL) {
        mln_chain_pool_release(c);
        return NULL;
    }
    b->left_pos = b->pos = b->start = buf;
    b->last = b->end = buf + blen;
    b->in_memory = 1;
    b->last_buf = 1;

    portal_littleendian_encode(buf, sizeof(msg->seqHigh), msg->seqHigh);
    portal_littleendian_encode(buf, sizeof(msg->seqLow), msg->seqLow);
    portal_littleendian_encode(buf, sizeof(msg->type), msg->type);
    memcpy(buf, msg->serverKey, PORTAL_KEY_LEN);
    buf += PORTAL_KEY_LEN;
    memcpy(buf, msg->clientKey, PORTAL_KEY_LEN);
    buf += PORTAL_KEY_LEN;
    portal_littleendian_encode(buf, sizeof(msg->len), msg->len);
    memcpy(buf, msg->buf, msg->len);
    buf += msg->len;
    memcpy(buf, msg->hash, PORTAL_KEY_LEN);

    return c;
}

mln_chain_t *portal_msg_extractFromMsg(mln_alloc_t *pool, portal_message_t *msg)
{
    if (!msg->len) {
        mln_log(error, "Length cannot be zero.\n");
        return NULL;
    }
    mln_chain_t *c;
    mln_buf_t *b;
    mln_u8ptr_t buf;
    mln_u8_t tmpbuf[256];
    mln_u8_t hash[PORTAL_KEY_LEN];
    mln_sha256_t sha;

    mln_sha256_init(&sha);
    mln_sha256_calc(&sha, msg->buf, msg->len, 1);
    mln_sha256_tobytes(&sha, hash, PORTAL_KEY_LEN);
    if (memcmp(msg->hash, hash, PORTAL_KEY_LEN)) {
        mln_log(error, "Message hash not identical.\n");
        return NULL;
    }

    if ((c = mln_chain_new(pool)) == NULL) {
        mln_log(error, "No memory.\n");
        return NULL;
    }
    if ((b = mln_buf_new(pool)) == NULL) {
        mln_log(error, "No memory.\n");
        mln_chain_pool_release(c);
        return NULL;
    }
    c->buf = b;
    if ((buf = (mln_u8ptr_t)mln_alloc_m(pool, msg->len)) == NULL) {
        mln_log(error, "No memory.\n");
        mln_chain_pool_release(c);
        return NULL;
    }
    b->left_pos = b->pos = b->start = buf;
    b->last = b->end = buf + msg->len;
    b->in_memory = 1;
    b->last_buf = 1;
    mln_rc4_init(tmpbuf, gCertKey->data, gCertKey->len);
    mln_rc4_calc(tmpbuf, msg->buf, msg->len);
    memcpy(buf, msg->buf, msg->len);

    return c;
}

portal_message_t *portal_msg_packUpMsg(portal_message_t *msg, \
                                       mln_chain_t **c, \
                                       mln_u8ptr_t serverKey, \
                                       mln_u8ptr_t clientKey, \
                                       mln_u32_t type, \
                                       mln_u64_t sndSeqHigh, \
                                       mln_u64_t sndSeqLow)
{
    mln_chain_t *fr;
    mln_u32_t len;
    mln_sha256_t sha;

    while (c != NULL && *c != NULL) {
        if ((*c)->buf == NULL || !mln_buf_left_size((*c)->buf)) {
            fr = *c;
            *c = (*c)->next;
            mln_chain_pool_release(fr);
            continue;
        }
        break;
    }

    portal_msg_init(msg);
    msg->seqHigh = sndSeqHigh;
    msg->seqLow = sndSeqLow;
    msg->type = type;
    len = c==NULL? sizeof(mln_u32_t): (*c)->buf->last - (*c)->buf->left_pos;
    msg->len = len > PORTAL_MESSAGE_UNITLEN? PORTAL_MESSAGE_UNITLEN: len;
    if (serverKey != NULL)
        memcpy(msg->serverKey, serverKey, PORTAL_KEY_LEN);
    if (clientKey != NULL)
        memcpy(msg->clientKey, clientKey, PORTAL_KEY_LEN);
    if (c != NULL) {
        memcpy(msg->buf, (*c)->buf->left_pos, msg->len);
        mln_u8_t tmpbuf[256];
        mln_rc4_init(tmpbuf, gCertKey->data, gCertKey->len);
        mln_rc4_calc(tmpbuf, msg->buf, msg->len);
        (*c)->buf->left_pos += msg->len;

        if (!mln_buf_left_size((*c)->buf)) {
            while (*c != NULL) {
                if ((*c)->buf == NULL || !mln_buf_left_size((*c)->buf)) {
                    fr = *c;
                    *c = (*c)->next;
                    mln_chain_pool_release(fr);
                    continue;
                }
                break;
            }
        }
    } else if (type != PORTAL_MSG_TYPE_DATA) {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        srandom(tv.tv_sec*1000000+tv.tv_usec);
        mln_u32_t uninit = random() & 0xffffffff;
        memcpy(msg->buf, &uninit, msg->len);
    } else {
        mln_log(error, "Shouldn't be here.\n");
        abort();
    }
    mln_sha256_init(&sha);
    mln_sha256_calc(&sha, msg->buf, msg->len, 1);
    mln_sha256_tobytes(&sha, msg->hash, PORTAL_KEY_LEN);

    return msg;
}



