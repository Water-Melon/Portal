/*
 * Copyright (C) Niklaus F.Schen.
 */
#ifndef __PORTAL_H
#define __PORTAL_H

#include "mln_conf.h"
#include "mln_rbtree.h"
#include "mln_sha.h"
#include "mln_log.h"

#define PORTAL_KEY_LEN             (__M_SHA_BUFLEN>>1)

extern mln_rbtree_t *gInnerSet;
extern mln_rbtree_t *gOuterSet;
extern void *GlobalUnusedVar;
extern mln_size_t gTunnelNum;
extern mln_u8_t gIsServer;
extern mln_u8_t gIsPositive;
extern char gOuterIP[48];
extern char gInnerIP[48];
extern mln_u16_t gOuterPort;
extern mln_u16_t gInnerPort;
extern mln_string_t *gCertKey;
extern mln_sauto_t gInnerTimeout;
extern mln_sauto_t gOuterTimeout;
extern mln_sauto_t gRetryTimeout;
extern mln_string_t *gAs;

#endif



