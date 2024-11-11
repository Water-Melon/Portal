/*
 * Copyright (C) Niklaus F.Schen.
 */

#include "portal.h"
#include "server.h"
#include "client.h"
#include "proxy.h"
#include "broadcaster.h"
#include "connection.h"
#include "mln_framework.h"
#include "mln_path.h"

/*
 * global variables
 */
mln_rbtree_t *gInnerSet;
mln_rbtree_t *gOuterSet;
void *GlobalUnusedVar;
mln_size_t gTunnelNum;
mln_u8_t gIsServer;
mln_u8_t gIsPositive;
char gOuterIP[48];
char gInnerIP[48];
mln_u16_t gOuterPort;
mln_u16_t gInnerPort;
mln_string_t *gCertKey;
mln_sauto_t gInnerTimeout;
mln_sauto_t gOuterTimeout;
mln_sauto_t gRetryTimeout;
mln_string_t *gAs;
char *gConfPath = NULL;


static char mln_domain_portal[] = "portal";
static char mln_cmd_certKey[] = "certify_token";
static char mln_cmd_tunnelNum[] = "tunnel_number";
static char mln_cmd_outer[] = "outerAddr";
static char mln_cmd_inner[] = "innerAddr";
static char mln_cmd_role[] = "role";
static char mln_cmd_mode[] = "mode";
static char mln_cmd_workerNum[] = "worker_proc";
static char mln_cmd_role_server[] = "server";
static char mln_cmd_role_client[] = "client";
static char mln_cmd_inner_timeout[] = "inner_timeout";
static char mln_cmd_outer_timeout[] = "outer_timeout";
static char mln_cmd_retry_timeout[] = "retry_timeout";
static char mln_cmd_mode_positive[] = "positive";
static char mln_cmd_mode_negative[] = "negative";
static char mln_cmd_as[] = "as";
static char mln_cmd_as_tunnel[] = "tunnel";
static char mln_cmd_as_proxy[] = "proxy";
static char mln_cmd_as_broadcaster[] = "broadcaster";

static void portal_args_parse(int argc, char *argv[]);
static char *portal_path_conf(void);
static int mln_global_init(void);
static void mln_worker_process(mln_event_t *ev);

int main(int argc, char *argv[])
{
    portal_args_parse(argc, argv);
    struct mln_framework_attr fattr;
    fattr.argc = argc;
    fattr.argv = argv;
    fattr.global_init = mln_global_init;
    fattr.main_thread = NULL;
    fattr.master_process = NULL;
    fattr.worker_process = mln_worker_process;
    return mln_framework_init(&fattr);
}

static void portal_args_parse(int argc, char *argv[])
{
    int i, len;
    for (i = 1; i < argc; ++i) {
        len = strlen(argv[i]);
        if (argv[i][0] == '-' && len == 2) {
            switch (argv[i][1]) {
                case 'c':
                    if (i + 1 >= argc) {
                        fprintf(stderr, "Lack of configuration path\n");
                        exit(1);
                    }
                    gConfPath = argv[++i];
                    mln_path_hook_set(m_p_conf, portal_path_conf);
                    break;
                case 'v':
                    printf("Version 1.0.0\n");
                    exit(0);
                case 'h':
                    printf("%s [-c conf_path | -h | -v]\n", argv[0]);
                    printf("-c\tdesignate configuration file path\n");
                    printf("-h\tshow help information\n");
                    printf("-v\tshow version\n");
                    exit(0);
                default:
                    fprintf(stderr, "Parameter [-%c] not supported\n", argv[i][1]);
                    exit(1);
            }
            continue;
        }
        fprintf(stderr, "Parameter [%s] not supported\n", argv[i]);
        exit(1);
    }
}

static char *portal_path_conf(void)
{
    return gConfPath;
}

static int mln_global_init(void)
{
    struct mln_rbtree_attr rbattr;
    mln_conf_t *cf = mln_conf();
    mln_conf_domain_t *cd = cf->search(cf, "main");
    mln_conf_cmd_t *cc;
    mln_conf_item_t *ci;
    char addr[24], *pos = NULL;

    /*check work_proc*/
    if ((cc = cd->search(cd, mln_cmd_workerNum)) == NULL) {
        fprintf(stderr, "Command '%s' required.\n", mln_cmd_workerNum);
        return -1;
    }
    if ((ci = cc->search(cc, 1)) == NULL) {
        fprintf(stderr, "Command '%s' need one parameter.\n", mln_cmd_workerNum);
        return -1;
    }
    if (ci->type != CONF_INT || ci->val.i != 1) {
        fprintf(stderr, "Invalid parameter of command '%s'.\n", mln_cmd_workerNum);
        return -1;
    }

    cd = cf->search(cf, mln_domain_portal);
    if (cd == NULL) {
        fprintf(stderr, "Domain '%s' is required.\n", mln_domain_portal);
        return -1;
    }

    /*get tunnel number*/
    if ((cc = cd->search(cd, mln_cmd_tunnelNum)) == NULL) {
        fprintf(stderr, "Command '%s' required.\n", mln_cmd_tunnelNum);
        return -1;
    }
    if ((ci = cc->search(cc, 1)) == NULL) {
        fprintf(stderr, "Command '%s' need one parameter.\n", mln_cmd_tunnelNum);
        return -1;
    }
    if (ci->type != CONF_INT || (gTunnelNum = ci->val.i) < 1) {
        fprintf(stderr, "Invalid parameter of command '%s'.\n", mln_cmd_tunnelNum);
        return -1;
    }

    /*get inner timeout*/
    if ((cc = cd->search(cd, mln_cmd_inner_timeout)) == NULL) {
        fprintf(stderr, "Command '%s' required.\n", mln_cmd_inner_timeout);
        return -1;
    }
    if ((ci = cc->search(cc, 1)) == NULL) {
        fprintf(stderr, "Command '%s' need one parameter.\n", mln_cmd_inner_timeout);
        return -1;
    }
    if (ci->type != CONF_INT || (gInnerTimeout = ci->val.i) < -1) {
        fprintf(stderr, "Invalid parameter of command '%s'.\n", mln_cmd_inner_timeout);
        return -1;
    }

    /*get outer timeout*/
    if ((cc = cd->search(cd, mln_cmd_outer_timeout)) == NULL) {
        fprintf(stderr, "Command '%s' required.\n", mln_cmd_outer_timeout);
        return -1;
    }
    if ((ci = cc->search(cc, 1)) == NULL) {
        fprintf(stderr, "Command '%s' need one parameter.\n", mln_cmd_outer_timeout);
        return -1;
    }
    if (ci->type != CONF_INT || (gOuterTimeout = ci->val.i) < -1) {
        fprintf(stderr, "Invalid parameter of command '%s'.\n", mln_cmd_outer_timeout);
        return -1;
    }

    /*get retry timeout*/
    if ((cc = cd->search(cd, mln_cmd_retry_timeout)) == NULL) {
        fprintf(stderr, "Command '%s' required.\n", mln_cmd_retry_timeout);
        return -1;
    }
    if ((ci = cc->search(cc, 1)) == NULL) {
        fprintf(stderr, "Command '%s' need one parameter.\n", mln_cmd_retry_timeout);
        return -1;
    }
    if (ci->type != CONF_INT || (gRetryTimeout = ci->val.i) < -1) {
        fprintf(stderr, "Invalid parameter of command '%s'.\n", mln_cmd_retry_timeout);
        return -1;
    }

    /*get role*/
    if ((cc = cd->search(cd, mln_cmd_role)) == NULL) {
        fprintf(stderr, "Command '%s' required.\n", mln_cmd_role);
        return -1;
    }
    if ((ci = cc->search(cc, 1)) == NULL) {
        fprintf(stderr, "Command '%s' need one parameter.\n", mln_cmd_role);
        return -1;
    }
    if (ci->type != CONF_STR) {
        fprintf(stderr, "Invalid parameter of command '%s'.\n", mln_cmd_role);
        return -1;
    }
    if (!mln_string_const_strcmp(ci->val.s, mln_cmd_role_server)) {
        gIsServer = 1;
    } else if (!mln_string_const_strcmp(ci->val.s, mln_cmd_role_client)) {
        gIsServer = 0;
    } else {
        fprintf(stderr, "Invalid parameter of command '%s'.\n", mln_cmd_role);
        return -1;
    }

    /*get mode*/
    if ((cc = cd->search(cd, mln_cmd_mode)) == NULL) {
        fprintf(stderr, "Command '%s' required.\n", mln_cmd_mode);
        return -1;
    }
    if ((ci = cc->search(cc, 1)) == NULL) {
        fprintf(stderr, "Command '%s' need one parameter.\n", mln_cmd_mode);
        return -1;
    }
    if (ci->type != CONF_STR) {
        fprintf(stderr, "Invalid parameter of command '%s'.\n", mln_cmd_mode);
        return -1;
    }
    if (!mln_string_const_strcmp(ci->val.s, mln_cmd_mode_positive)) {
        gIsPositive = 1;
    } else if (!mln_string_const_strcmp(ci->val.s, mln_cmd_mode_negative)) {
        gIsPositive = 0;
    } else {
        fprintf(stderr, "Invalid parameter of command '%s'.\n", mln_cmd_mode);
        return -1;
    }

    /*get certKey*/
    if ((cc = cd->search(cd, mln_cmd_certKey)) == NULL) {
        fprintf(stderr, "Command '%s' required.\n", mln_cmd_certKey);
        return -1;
    }
    if ((ci = cc->search(cc, 1)) == NULL) {
        fprintf(stderr, "Command '%s' need one parameter.\n", mln_cmd_certKey);
        return -1;
    }
    if (ci->type != CONF_STR) {
        fprintf(stderr, "Invalid parameter of command '%s'.\n", mln_cmd_certKey);
        return -1;
    }
    gCertKey = mln_string_dup(ci->val.s);
    if (gCertKey == NULL) {
        fprintf(stderr, "No memoru.\n");
        return -1;
    }

    /*outer address*/
    if ((cc = cd->search(cd, mln_cmd_outer)) == NULL) {
        fprintf(stderr, "Command '%s' required.\n", mln_cmd_outer);
        return -1;
    }
    if ((ci = cc->search(cc, 1)) == NULL) {
        fprintf(stderr, "Command '%s' need one parameter.\n", mln_cmd_outer);
        return -1;
    }
    if (ci->type != CONF_STR) {
        fprintf(stderr, "Invalid parameter of command '%s'.\n", mln_cmd_outer);
        return -1;
    }
    if (ci->val.s->len >= sizeof(addr)) {
        fprintf(stderr, "Invalid parameter of command '%s'.\n", mln_cmd_outer);
        return -1;
    }
    memcpy(addr, ci->val.s->data, ci->val.s->len);
    addr[ci->val.s->len] = 0;
    if ((pos = strchr(addr, ':')) == NULL) {
        fprintf(stderr, "Invalid parameter of command '%s'.\n", mln_cmd_outer);
        return -1;
    }
    memcpy(gOuterIP, addr, pos - addr);
    if (!(gOuterPort = atoi(pos + 1))) {
        fprintf(stderr, "Invalid parameter of command '%s'.\n", mln_cmd_outer);
        return -1;
    }

    /*inner address*/
    if ((cc = cd->search(cd, mln_cmd_inner)) == NULL) {
        fprintf(stderr, "Command '%s' required.\n", mln_cmd_inner);
        return -1;
    }
    if ((ci = cc->search(cc, 1)) == NULL) {
        fprintf(stderr, "Command '%s' need one parameter.\n", mln_cmd_inner);
        return -1;
    }
    if (ci->type != CONF_STR) {
        fprintf(stderr, "Invalid parameter of command '%s'.\n", mln_cmd_inner);
        return -1;
    }
    if (ci->val.s->len >= sizeof(addr)) {
        fprintf(stderr, "Invalid parameter of command '%s'.\n", mln_cmd_inner);
        return -1;
    }
    memcpy(addr, ci->val.s->data, ci->val.s->len);
    addr[ci->val.s->len] = 0;
    if ((pos = strchr(addr, ':')) == NULL) {
        fprintf(stderr, "Invalid parameter of command '%s'.\n", mln_cmd_inner);
        return -1;
    }
    memcpy(gInnerIP, addr, pos - addr);
    if (!(gInnerPort = atoi(pos + 1))) {
        fprintf(stderr, "Invalid parameter of command '%s'.\n", mln_cmd_inner);
        return -1;
    }

    /*as*/
    if ((cc = cd->search(cd, mln_cmd_as)) == NULL) {
        fprintf(stderr, "Command '%s' required.\n", mln_cmd_as);
        return -1;
    }
    if ((ci = cc->search(cc, 1)) == NULL || ci->type != CONF_STR) {
        fprintf(stderr, "Invalid parameter of command '%s'.\n", mln_cmd_as);
        return -1;
    }
    gAs = ci->val.s;

    /*sets*/
    rbattr.cmp = (rbtree_cmp)portal_connection_cmp;
    rbattr.data_free = (rbtree_free_data)portal_connection_free;
    if ((gOuterSet = mln_rbtree_new(&rbattr)) == NULL) {
        fprintf(stderr, "No memory.\n");
        return -1;
    }
    if ((gInnerSet = mln_rbtree_new(&rbattr)) == NULL) {
        fprintf(stderr, "No memory.\n");
        return -1;
    }
    return 0;
}

static void mln_worker_process(mln_event_t *ev)
{
    if (!mln_string_const_strcmp(gAs, mln_cmd_as_tunnel)) {
        gIsServer? portal_server_entrance(ev): portal_client_entrance(ev);
    } else if (!mln_string_const_strcmp(gAs, mln_cmd_as_proxy)) {
        portal_proxy_entrance(ev);
    } else if (!mln_string_const_strcmp(gAs, mln_cmd_as_broadcaster)) {
        portal_broadcaster_entrance(ev);
    } else {
        mln_log(error, "Invalid configuration '%s'\n", mln_cmd_as);
        exit(1);
    }
}

