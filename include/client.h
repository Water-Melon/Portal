/*
 * Copyright (C) Niklaus F.Schen.
 */
#ifndef __PORTAL_CLIENT_H
#define __PORTAL_CLIENT_H

#include "portal.h"
#include "connection.h"

typedef struct fdClose_dataSet_s{
    conn_type_t    type;
    void          *data;
} fdClose_dataSet_t;

extern void portal_client_entrance(mln_event_t *ev) __NONNULL1(1);

#endif



