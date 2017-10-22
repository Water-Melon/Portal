
/*
 * Copyright (C) Niklaus F.Schen.
 */

#ifndef __MLN_GLOBAL_H
#define __MLN_GLOBAL_H
#include <stdio.h>
#include "mln_types.h"
#include "mln_conf.h"

#ifndef __MLN_DEFINE
#define EXTERN extern
#else
#define EXTERN
#endif

EXTERN void *GlobalUnusedVar;
EXTERN mln_size_t gTunnelNum;
EXTERN mln_u8_t gIsServer;
EXTERN mln_u8_t gIsPositive;
EXTERN char gOuterIP[48];
EXTERN char gInnerIP[48];
EXTERN mln_u16_t gOuterPort;
EXTERN mln_u16_t gInnerPort;
EXTERN mln_string_t *gCertKey;
EXTERN mln_sauto_t gInnerTimeout;
EXTERN mln_sauto_t gOuterTimeout;
EXTERN mln_sauto_t gRetryTimeout;

#endif

