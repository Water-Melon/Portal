/*
 * Copyright (C) Niklaus F.Schen.
 */
#ifndef __PORTAL_H
#define __PORTAL_H

#include "mln_core.h"
#include "mln_conf.h"
#include "mln_global.h"
#include "mln_rbtree.h"
#include "mln_sha.h"

#define PORTAL_KEY_LEN             (__M_SHA_BUFLEN>>1)

extern mln_rbtree_t *gInnerSet;
extern mln_rbtree_t *gOuterSet;

#endif



