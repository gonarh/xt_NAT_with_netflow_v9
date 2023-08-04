#include <linux/module.h>
#include <linux/timer.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/jhash.h>
#include <linux/vmalloc.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/version.h>
#include <linux/netfilter/x_tables.h>
#include <linux/inet.h>
#include <linux/proc_fs.h>
#include <net/tcp.h>
#include "compat.h"
#include "xt_NAT.h"

#define FLAG_REPLIED   (1 << 0) /* 000001 */
#define FLAG_TCP_FIN   (1 << 1) /* 000010 */

#define TCP_SYN_ACK 0x12
#define TCP_FIN_RST 0x05

static LIST_HEAD(usock_list);
static int sndbuf = 1310720;
static int flowsetID = 300;
static unsigned int pdu_data_records = 0;
static unsigned int pdu_seq = 0;
struct netflow9_pdu pdu;
struct netflow9_template templateV9;
static DEFINE_SPINLOCK(nfsend_lock);

static atomic64_t sessions_active = ATOMIC_INIT(0);
static atomic64_t users_active = ATOMIC_INIT(0);
static atomic64_t sessions_tried = ATOMIC_INIT(0);
static atomic64_t sessions_created = ATOMIC_INIT(0);
static atomic64_t dnat_dropped = ATOMIC_INIT(0);
static atomic64_t frags = ATOMIC_INIT(0);
static atomic64_t related_icmp = ATOMIC_INIT(0);

static char nat_pool_buf[128] = "127.0.0.1-127.0.0.1";
static char *nat_pool = nat_pool_buf;
module_param(nat_pool, charp, 0444);
MODULE_PARM_DESC(nat_pool, "NAT pool range (addr_start-addr_end), default = 127.0.0.1-127.0.0.1");

static int nat_hash_size = 256 * 1024;
module_param(nat_hash_size, int, 0444);
MODULE_PARM_DESC(nat_hash_size, "nat hash size, default = 256k");

static int users_hash_size = 64 * 1024;
module_param(users_hash_size, int, 0444);
MODULE_PARM_DESC(users_hash_size, "users hash size, default = 64k");

static char nf_dest_buf[128] = "";
static char *nf_dest = nf_dest_buf;
module_param(nf_dest, charp, 0444);
MODULE_PARM_DESC(nf_dest, "Netflow v9 collectors (addr1:port1[,addr2:port2]), default = none");

u_int32_t nat_htable_vector = 0;
u_int32_t users_htable_vector = 0;

static spinlock_t *create_session_lock;

static DEFINE_SPINLOCK(sessions_timer_lock);
static DEFINE_SPINLOCK(users_timer_lock);
static struct timer_list sessions_cleanup_timer, users_cleanup_timer, nf_send_timer;

struct proc_dir_entry *proc_net_nat;

struct netflow_sock {
    struct list_head list;
    struct socket *sock;
    struct sockaddr_storage addr;   // destination
};

struct xt_nat_htable {
    uint8_t use;
    spinlock_t lock;
    struct hlist_head session;
};

struct nat_htable_ent {
    struct rcu_head rcu;
    struct hlist_node list_node;
    uint8_t  proto;
    uint32_t addr;
    uint16_t port;
    struct nat_session *data;
};

struct nat_session {
    uint32_t in_addr;
    uint32_t dst_addr;
    uint16_t dst_port;
    uint16_t in_port;
    uint16_t out_port;
    int16_t  timeout;
    uint8_t  flags;
};

struct xt_users_htable {
    uint8_t use;
    spinlock_t lock;
    struct hlist_head user;
};

struct user_htable_ent {
    struct rcu_head rcu;
    struct hlist_node list_node;
    uint32_t addr;
    uint16_t tcp_count;
    uint16_t udp_count;
    uint16_t other_count;
    uint8_t idle;
};

struct xt_users_htable *ht_users;

static u_int32_t nat_pool_start;
static u_int32_t nat_pool_end;

struct xt_nat_htable *ht_inner, *ht_outer;

static char *print_sockaddr(const struct sockaddr_storage *ss)
{
    static char buf[64];
    snprintf(buf, sizeof(buf), "%pISpc", ss);
    return buf;
}

static inline long timer_end(struct timespec64 start_time)
{
    struct timespec64 end_time;
    ktime_get_raw_ts64(&end_time);
    return(end_time.tv_nsec - start_time.tv_nsec);
}

static inline struct timespec64 timer_start(void)
{
    struct timespec64 start_time;
    ktime_get_raw_ts64(&start_time);
    return start_time;
}

static inline u_int32_t
get_pool_size(void)
{
    return ntohl(nat_pool_end)-ntohl(nat_pool_start)+1;
}

static inline u_int32_t
get_nat_addr(const u_int32_t addr)
{
    return htonl(ntohl(nat_pool_start)+reciprocal_scale(jhash_1word(addr, 0), get_pool_size()));
}

static inline u_int32_t
get_hash_nat_ent(const uint8_t proto, const u_int32_t addr, const uint16_t port)
{
    return reciprocal_scale(jhash_3words((u32)proto, addr, (u32)port, 0), nat_hash_size);
}

static inline u_int32_t
get_hash_user_ent(const u_int32_t addr)
{
    return reciprocal_scale(jhash_1word(addr, 0), users_hash_size);
}

static inline u_int32_t pool_table_create(void)
{
    unsigned int sz; /* (bytes) */
    unsigned int pool_size;
    int i;

    pool_size = get_pool_size();

    sz = sizeof(spinlock_t) * pool_size;
    create_session_lock = kzalloc(sz, GFP_KERNEL);

    if (create_session_lock == NULL)
        return -ENOMEM;

    for (i = 0; i < pool_size; i++) {
        spin_lock_init(&create_session_lock[i]);
    }

    printk(KERN_INFO "xt_NAT DEBUG: nat pool table mem: %d\n", sz);

    return 0;
}

void pool_table_remove(void)
{
    kfree(create_session_lock);

    printk(KERN_INFO "xt_NAT pool_table_remove DEBUG: removed\n");
}


static int users_htable_create(void)
{
    unsigned int sz; /* (bytes) */
    int i;

    sz = sizeof(struct xt_users_htable) * users_hash_size;
    ht_users = kzalloc(sz, GFP_KERNEL);

    if (ht_users == NULL)
        return -ENOMEM;

    for (i = 0; i < users_hash_size; i++) {
        spin_lock_init(&ht_users[i].lock);
        INIT_HLIST_HEAD(&ht_users[i].user);
        ht_users[i].use = 0;
    }

    printk(KERN_INFO "xt_NAT DEBUG: users htable mem: %d\n", sz);
    return 0;
}

void users_htable_remove(void)
{
    struct user_htable_ent *user;
    struct hlist_head *head;
    struct hlist_node *next;
    int i;

    for (i = 0; i < users_hash_size; i++) {
        spin_lock_bh(&ht_users[i].lock);
        head = &ht_users[i].user;
        hlist_for_each_entry_safe(user, next, head, list_node) {
            hlist_del_rcu(&user->list_node);
            ht_users[i].use--;
            kfree_rcu(user, rcu);
        }

        if (ht_users[i].use != 0) {
            printk(KERN_WARNING "xt_NAT users_htable_remove ERROR: bad use value: %d in element %d\n", ht_users[i].use, i);
        }
        spin_unlock_bh(&ht_users[i].lock);
    }
    kfree(ht_users);
    printk(KERN_INFO "xt_NAT users_htable_remove DONE\n");
    return;
}

void nat_htable_remove(void)
{
    struct nat_htable_ent *session;
    struct hlist_head *head;
    struct hlist_node *next;
    unsigned int i;
    void *p;

    for (i = 0; i < nat_hash_size; i++) {
        spin_lock_bh(&ht_inner[i].lock);
        head = &ht_inner[i].session;
        hlist_for_each_entry_safe(session, next, head, list_node) {
            hlist_del_rcu(&session->list_node);
            ht_inner[i].use--;
            kfree_rcu(session, rcu);
        }
        if (ht_inner[i].use != 0) {
            printk(KERN_WARNING "xt_NAT nat_htable_remove inner ERROR: bad use value: %d in element %d\n", ht_inner[i].use, i);
        }
        spin_unlock_bh(&ht_inner[i].lock);
    }

    for (i = 0; i < nat_hash_size; i++) {
        spin_lock_bh(&ht_outer[i].lock);
        head = &ht_outer[i].session;
        hlist_for_each_entry_safe(session, next, head, list_node) {
            hlist_del_rcu(&session->list_node);
            ht_outer[i].use--;
            p = session->data;
            kfree_rcu(session, rcu);
            kfree(p);
        }
        if (ht_outer[i].use != 0) {
            printk(KERN_WARNING "xt_NAT nat_htable_remove outer ERROR: bad use value: %d in element %d\n", ht_outer[i].use, i);
        }
        spin_unlock_bh(&ht_outer[i].lock);
    }
    printk(KERN_INFO "xt_NAT nat_htable_remove DONE\n");
    return;
}


static int nat_htable_create(void)
{
    unsigned int sz; /* (bytes) */
    int i;

    sz = sizeof(struct xt_nat_htable) * nat_hash_size;
    ht_inner = kzalloc(sz, GFP_KERNEL);
    if (ht_inner == NULL)
        return -ENOMEM;

    for (i = 0; i < nat_hash_size; i++) {
        spin_lock_init(&ht_inner[i].lock);
        INIT_HLIST_HEAD(&ht_inner[i].session);
        ht_inner[i].use = 0;
    }

    printk(KERN_INFO "xt_NAT DEBUG: sessions htable inner mem: %d\n", sz);

    ht_outer = kzalloc(sz, GFP_KERNEL);
    if (ht_outer == NULL)
        return -ENOMEM;

    for (i = 0; i < nat_hash_size; i++) {
        spin_lock_init(&ht_outer[i].lock);
        INIT_HLIST_HEAD(&ht_outer[i].session);
        ht_outer[i].use = 0;
    }

    printk(KERN_INFO "xt_NAT DEBUG: sessions htable outer mem: %d\n", sz);
    return 0;
}

struct nat_htable_ent *lookup_session(struct xt_nat_htable *ht, const uint8_t proto, const u_int32_t addr, const uint16_t port)
{
    struct nat_htable_ent *session;
    struct hlist_head *head;
    unsigned int hash;

    hash = get_hash_nat_ent(proto, addr, port);
    if (ht[hash].use == 0)
        return NULL;

    head = &ht[hash].session;
    hlist_for_each_entry_rcu(session, head, list_node) {
        if (session->addr == addr && session->port == port && session->proto == proto && session->data->timeout > 0) {
            return session;
        }
    }
    return NULL;
}

static uint16_t search_free_l4_port(const uint8_t proto, const u_int32_t nataddr, const uint16_t userport)
{
    uint16_t i, freeport;
    for(i = 0; i < 64512; i++) {
        freeport = ntohs(userport) + i;

        if (freeport < 1024) {
            freeport += 1024;
        }

        if(!lookup_session(ht_outer, proto, nataddr, htons(freeport))) {
            return htons(freeport);
        }
    }
    return 0;
}

static int check_user_limits(const u_int8_t proto, const u_int32_t addr)
{
    struct user_htable_ent *user;
    struct hlist_head *head;
    unsigned int hash, is_found, ret;
    unsigned int sessions, session_limit;

    hash = get_hash_user_ent(addr);
    rcu_read_lock_bh();
    head = &ht_users[hash].user;
    is_found=0;
    hlist_for_each_entry_rcu(user, head, list_node) {
        if (user->addr == addr && user->idle < 15) {
            if (proto == IPPROTO_TCP) {
                sessions = user->tcp_count;
                session_limit = 4096;
            } else if (proto == IPPROTO_UDP) {
                sessions = user->udp_count;
                session_limit = 4096;
            } else {
                sessions = user->other_count;
                session_limit = 4096;
            }
            is_found=1;
            break;
        }
    }

    ret=1;
    if (is_found==1) {
        if (sessions < session_limit) {
            ret=1;
        } else {
            ret=0;
        }
    } else {
        ret=1;
    }
    rcu_read_unlock_bh();
    return ret;
}

void update_user_limits(const u_int8_t proto, const u_int32_t addr, const int8_t operation)
{
    struct user_htable_ent *user;
    struct hlist_head *head;
    unsigned int hash, is_found;
    unsigned int sz;

    hash = get_hash_user_ent(addr);
    spin_lock_bh(&ht_users[hash].lock);
    head = &ht_users[hash].user;
    is_found=0;
    hlist_for_each_entry(user, head, list_node) {
        if (user->addr == addr && user->idle < 15) {
            is_found=1;
            break;
        }
    }

    if (likely(is_found==1)) {
        user->idle = 0;
        if (proto == IPPROTO_TCP) {
            user->tcp_count += operation;
        } else if (proto == IPPROTO_UDP) {
            user->udp_count += operation;
        } else {
            user->other_count += operation;
        }
    } else {
        sz = sizeof(struct user_htable_ent);
        user = kzalloc(sz, GFP_ATOMIC);

        if (user == NULL) {
            printk(KERN_WARNING "xt_NAT update_user_limits ERROR: Cannot allocate memory for user_session\n");
            spin_unlock_bh(&ht_users[hash].lock);
            return;
        }

        user->addr = addr;
        user->tcp_count = 0;
        user->udp_count = 0;
        user->other_count = 0;
        user->idle = 0;

        if (proto == IPPROTO_TCP) {
            user->tcp_count += operation;
        } else if (proto == IPPROTO_UDP) {
            user->udp_count += operation;
        } else {
            user->other_count += operation;
        }
        hlist_add_head_rcu(&user->list_node, &ht_users[hash].user);
        ht_users[hash].use++;
        atomic64_inc(&users_active);
    }

    spin_unlock_bh(&ht_users[hash].lock);
    return;
}

/* socket code */
static void sk_error_report(struct sock *sk)
{
    sk->sk_err = 0;
    return;
}

static struct socket *usock_open_sock(const struct sockaddr_storage *addr, void *user_data)
{
    struct socket *sock;
    int error;

    if ((error = sock_create_kern(addr->ss_family, SOCK_DGRAM, IPPROTO_UDP, &sock)) < 0) {
        printk(KERN_WARNING "xt_NAT NEL: sock_create_kern error %d\n", -error);
        return NULL;
    }
    sock->sk->sk_allocation = GFP_ATOMIC;
    sock->sk->sk_prot->unhash(sock->sk); /* hidden from input */
    sock->sk->sk_error_report = &sk_error_report; /* clear ECONNREFUSED */
    sock->sk->sk_user_data = user_data; /* usock */

    if (sndbuf < SOCK_MIN_SNDBUF)
	sndbuf = SOCK_MIN_SNDBUF;

    if (sndbuf)
        sock->sk->sk_sndbuf = sndbuf;
    else
        sndbuf = sock->sk->sk_sndbuf;
    error = sock->ops->connect(sock, (struct sockaddr *)addr, sizeof(*addr), 0);
    if (error < 0) {
        printk(KERN_WARNING "xt_NAT NEL: error connecting UDP socket %d,"
               " don't worry, will try reconnect later.\n", -error);
        /* ENETUNREACH when no interfaces */
        sock_release(sock);
        return NULL;
    }
    return sock;
}

static void netflow_sendmsg(void *buffer, const int len)
{
    struct msghdr msg = { .msg_flags = MSG_DONTWAIT|MSG_NOSIGNAL };
    struct kvec iov = { buffer, len };
    struct netflow_sock *usock;
    int ret;

    list_for_each_entry(usock, &usock_list, list) {
        if (!usock->sock)
            usock->sock = usock_open_sock(&usock->addr, usock);

        if (!usock->sock)
            continue;

        ret = kernel_sendmsg(usock->sock, &msg, &iov, 1, (size_t)len);
        if (ret == -EINVAL) {
            if (usock->sock)
                sock_release(usock->sock);
            usock->sock = NULL;
        } else if (ret == -EAGAIN) {
            printk(KERN_WARNING "xt_NAT NEL: increase sndbuf!\n");
        }
    }
}

static void netflow_export_pdu_v9(void)
{
    struct timespec64 ts;
    int pdusize;

    if (!pdu_data_records)
        return;

    pdu.version		= htons(9);
    pdu.nr_records	= htons(pdu_data_records + 1);
    pdu.ts_uptime	= htonl(jiffies_to_msecs(jiffies));
    ktime_get_real_ts64(&ts);
    pdu.ts_usecs	= htonl(ts.tv_sec);
    pdu.seq		= htonl(pdu_seq);
    pdu.srcID		= 0;
    pdu.template_V9	= templateV9;
    pdu.FlowSetId	= htons(flowsetID);
    pdu.FlowSetIdSize	= sizeof(struct netflow9_record) * pdu_data_records;
    pdusize = NETFLOW9_HEADER_SIZE + pdu.FlowSetIdSize;
    pdu.FlowSetIdSize	= htons(pdu.FlowSetIdSize+4);
    netflow_sendmsg(&pdu, pdusize);
    pdu_seq++;
    pdu_data_records = 0;
}

static void netflow_export_flow_v9(const uint8_t proto, const u_int32_t srcaddr, const uint16_t srcport, const u_int32_t dstaddr, const uint16_t dstport, const u_int32_t nataddr, const uint16_t natport, const int nat_event)
{
    struct netflow9_record *rec;

    spin_lock_bh(&nfsend_lock);

    rec = &pdu.flow[pdu_data_records++];

    rec->protocol	= proto;
    rec->s_port		= srcport;
    rec->s_addr		= srcaddr;
    rec->d_port		= dstport;
    rec->d_addr		= dstaddr;
    rec->n_addr		= nataddr;
    rec->n_port		= natport;
    rec->event		= nat_event;

    if (pdu_data_records == NETFLOW9_RECORDS_MAX)
        netflow_export_pdu_v9();

    spin_unlock_bh(&nfsend_lock);
}

struct nat_htable_ent *create_nat_session(const uint8_t proto, const u_int32_t useraddr, const uint16_t userport, const u_int32_t dstaddr, const uint16_t dstport, const u_int32_t nataddr)
{
    unsigned int hash;
    struct nat_htable_ent *session, *session2;
    struct nat_session *data_session;
    uint16_t natport;
    unsigned int sz;
    unsigned int nataddr_id;

    atomic64_inc(&sessions_tried);

    if (unlikely(check_user_limits(proto, useraddr) == 0)) {
        printk(KERN_NOTICE "xt_NAT: %pI4 exceed max allowed sessions\n", &useraddr);
        return NULL;
    }

    nataddr_id = ntohl(nataddr) - ntohl(nat_pool_start);
    spin_lock_bh(&create_session_lock[nataddr_id]);

    rcu_read_lock_bh();
    session = lookup_session(ht_inner, proto, useraddr, userport);
    if(unlikely(session)) {
        spin_unlock_bh(&create_session_lock[nataddr_id]);
        return lookup_session(ht_outer, proto, nataddr, session->data->out_port);
    }
    rcu_read_unlock_bh();

    if (likely(proto == IPPROTO_TCP || proto == IPPROTO_UDP || proto == IPPROTO_ICMP)) {
        rcu_read_lock_bh();
        natport = search_free_l4_port(proto, nataddr, userport);
        rcu_read_unlock_bh();
        if (natport == 0) {
            printk(KERN_WARNING "xt_NAT create_nat_session ERROR: Not found free nat port for %d %pI4:%u -> %pI4:XXXX\n", proto, &useraddr, userport, &nataddr);
            spin_unlock_bh(&create_session_lock[nataddr_id]);
            return NULL;
        }
    } else {
        natport = userport;
    }

    sz = sizeof(struct nat_session);
    data_session = kzalloc(sz, GFP_ATOMIC);

    if (unlikely(data_session == NULL)) {
        printk(KERN_WARNING "xt_NAT create_nat_session ERROR: Cannot allocate memory for data_session\n");
        spin_unlock_bh(&create_session_lock[nataddr_id]);
        return NULL;
    }

    sz = sizeof(struct nat_htable_ent);
    session = kzalloc(sz, GFP_ATOMIC);

    if (unlikely(session == NULL)) {
        printk(KERN_WARNING "xt_NAT ERROR: Cannot allocate memory for ht_inner session\n");
        kfree(data_session);
        spin_unlock_bh(&create_session_lock[nataddr_id]);
        return NULL;
    }

    sz = sizeof(struct nat_htable_ent);
    session2 = kzalloc(sz, GFP_ATOMIC);

    if (unlikely(session2 == NULL)) {
        printk(KERN_WARNING "xt_NAT ERROR: Cannot allocate memory for ht_outer session\n");
        kfree(data_session);
        kfree(session);
        spin_unlock_bh(&create_session_lock[nataddr_id]);
        return NULL;
    }

    data_session->in_addr = useraddr;
    data_session->in_port = userport;
    data_session->out_port = natport;
    data_session->dst_addr = dstaddr;
    data_session->dst_port = dstport;
    data_session->timeout = 30;
    data_session->flags = 0;

    session->proto = proto;
    session->addr = useraddr;
    session->port = userport;
    session->data = data_session;

    session2->proto = proto;
    session2->addr = nataddr;
    session2->port = natport;
    session2->data = data_session;

    hash = get_hash_nat_ent(proto, useraddr, userport);
    spin_lock_bh(&ht_inner[hash].lock);
    hlist_add_head_rcu(&session->list_node, &ht_inner[hash].session);
    ht_inner[hash].use++;
    spin_unlock_bh(&ht_inner[hash].lock);

    hash = get_hash_nat_ent(proto, nataddr, natport);
    spin_lock_bh(&ht_outer[hash].lock);
    hlist_add_head_rcu(&session2->list_node, &ht_outer[hash].session);
    ht_outer[hash].use++;
    spin_unlock_bh(&ht_outer[hash].lock);

    spin_unlock_bh(&create_session_lock[nataddr_id]);

    update_user_limits(proto, useraddr, 1);

    netflow_export_flow_v9(proto, useraddr, userport, dstaddr, dstport, nataddr, natport, 1);

    atomic64_inc(&sessions_created);
    atomic64_inc(&sessions_active);
    rcu_read_lock_bh();
    return lookup_session(ht_outer, proto, nataddr, natport);
}

static unsigned int
nat_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct udphdr *udp;
    struct icmphdr *icmp;
    struct nat_htable_ent *session;
    uint32_t nat_addr;
    uint16_t nat_port;
    skb_frag_t *frag;
    const struct xt_nat_tginfo *info = par->targinfo;

    if (unlikely(skb->protocol != htons(ETH_P_IP))) {
        printk(KERN_DEBUG "xt_NAT DEBUG: Drop not IP packet\n");
        return NF_DROP;
    }
    if (unlikely(ip_hdrlen(skb) != sizeof(struct iphdr))) {
        printk(KERN_DEBUG "xt_NAT DEBUG: Drop truncated IP packet\n");
        return NF_DROP;
    }

    ip = (struct iphdr *)skb_network_header(skb);

    if (unlikely(ip->frag_off & htons(IP_OFFSET))) {
        printk(KERN_DEBUG "xt_NAT DEBUG: Drop fragmented IP packet\n");
        return NF_DROP;
    }
    if (unlikely(ip->version != 4)) {
        printk(KERN_DEBUG "xt_NAT DEBUG: Drop not IPv4 IP packet\n");
        return NF_DROP;
    }

    if (info->variant == XTNAT_SNAT) {
        nat_addr = get_nat_addr(ip->saddr);

        if (ip->protocol == IPPROTO_TCP) {
            if (unlikely(skb->len < ip_hdrlen(skb) + sizeof(struct tcphdr))) {
                printk(KERN_DEBUG "xt_NAT SNAT: Drop truncated TCP packet\n");
                return NF_DROP;
            }
            skb_set_transport_header(skb, ip->ihl * 4);
            tcp = (struct tcphdr *)skb_transport_header(skb);
            skb_reset_transport_header(skb);

            rcu_read_lock_bh();
            session = lookup_session(ht_inner, ip->protocol, ip->saddr, tcp->source);
            if (session) {
                csum_replace4(&ip->check, ip->saddr, nat_addr);
                inet_proto_csum_replace4(&tcp->check, skb, ip->saddr, nat_addr, true);
                inet_proto_csum_replace2(&tcp->check, skb, tcp->source, session->data->out_port, true);

                ip->saddr = nat_addr;
                tcp->source = session->data->out_port;

                if (tcp->fin || tcp->rst) {
                    session->data->timeout=10;
                    session->data->flags |= FLAG_TCP_FIN;
                } else if (session->data->flags & FLAG_TCP_FIN) {
                    session->data->timeout=10;
                    session->data->flags &= ~FLAG_TCP_FIN;
                } else if ((session->data->flags & FLAG_REPLIED) == 0) {
                    session->data->timeout=30;
                } else {
                    session->data->timeout=300;
                }

                rcu_read_unlock_bh();
            } else {
                rcu_read_unlock_bh();
                session = create_nat_session(ip->protocol, ip->saddr, tcp->source, ip->daddr, tcp->dest, nat_addr);
                if (session == NULL) {
                    return NF_DROP;
                }

                csum_replace4(&ip->check, ip->saddr, session->addr);
                inet_proto_csum_replace4(&tcp->check, skb, ip->saddr, session->addr, true);
                inet_proto_csum_replace2(&tcp->check, skb, session->data->in_port, session->data->out_port, true);
                ip->saddr = session->addr;
                tcp->source = session->data->out_port;
                rcu_read_unlock_bh();
            }

        } else if (ip->protocol == IPPROTO_UDP) {
            if (unlikely(skb->len < ip_hdrlen(skb) + sizeof(struct udphdr))) {
                printk(KERN_DEBUG "xt_NAT SNAT: Drop truncated UDP packet\n");
                return NF_DROP;
            }

            skb_set_transport_header(skb, ip->ihl * 4);
            udp = (struct udphdr *)skb_transport_header(skb);
            skb_reset_transport_header(skb);

            rcu_read_lock_bh();
            session = lookup_session(ht_inner, ip->protocol, ip->saddr, udp->source);
            if (session) {
                csum_replace4(&ip->check, ip->saddr, nat_addr);
                if (udp->check) {
                    inet_proto_csum_replace4(&udp->check, skb, ip->saddr, nat_addr, true);
                    inet_proto_csum_replace2(&udp->check, skb, udp->source, session->data->out_port, true);
                }
                ip->saddr = nat_addr;
                udp->source = session->data->out_port;
                if ((session->data->flags & FLAG_REPLIED) == 0) {
                    session->data->timeout=30;
                } else {
                    session->data->timeout=300;
                }
                rcu_read_unlock_bh();
            } else {
                rcu_read_unlock_bh();
                session = create_nat_session(ip->protocol, ip->saddr, udp->source, ip->daddr, udp->dest, nat_addr);
                if (session == NULL) {
                    return NF_DROP;
                }
                csum_replace4(&ip->check, ip->saddr, session->addr);
                if (udp->check) {
                    inet_proto_csum_replace4(&udp->check, skb, ip->saddr, session->addr, true);
                    inet_proto_csum_replace2(&udp->check, skb, session->data->in_port, session->data->out_port, true);
                }
                ip->saddr = session->addr;
                udp->source = session->data->out_port;
                rcu_read_unlock_bh();
            }
        } else if (ip->protocol == IPPROTO_ICMP) {
            if (unlikely(skb->len < ip_hdrlen(skb) + sizeof(struct icmphdr))) {
                printk(KERN_DEBUG "xt_NAT SNAT: Drop truncated ICMP packet\n");
                return NF_DROP;
            }

            skb_set_transport_header(skb, ip->ihl * 4);
            icmp = (struct icmphdr *)skb_transport_header(skb);
            skb_reset_transport_header(skb);

            nat_port = 0;
            if (icmp->type == 0 || icmp->type == 8) {
                nat_port = icmp->un.echo.id;
            }

            rcu_read_lock_bh();
            session = lookup_session(ht_inner, ip->protocol, ip->saddr, nat_port);
            if (session) {
                csum_replace4(&ip->check, ip->saddr, nat_addr);
                ip->saddr = nat_addr;

                if (icmp->type == 0 || icmp->type == 8) {
                    inet_proto_csum_replace2(&icmp->checksum, skb, nat_port, session->data->out_port, true);
                    icmp->un.echo.id = session->data->out_port;
                }
                session->data->timeout=30;
                rcu_read_unlock_bh();
            } else {
                rcu_read_unlock_bh();
                session = create_nat_session(ip->protocol, ip->saddr, nat_port, ip->daddr, nat_port, nat_addr);
                if (session == NULL) {
                    return NF_DROP;
                }
                csum_replace4(&ip->check, ip->saddr, session->addr);
                ip->saddr = session->addr;
                if (icmp->type == 0 || icmp->type == 8) {
                    inet_proto_csum_replace2(&icmp->checksum, skb, nat_port, session->data->out_port, true);
                    icmp->un.echo.id = session->data->out_port;
                }
                rcu_read_unlock_bh();
            }
        } else {
            rcu_read_lock_bh();
            session = lookup_session(ht_inner, ip->protocol, ip->saddr, 0);
            if (session) {
                csum_replace4(&ip->check, ip->saddr, nat_addr);
                ip->saddr = nat_addr;
                if ((session->data->flags & FLAG_REPLIED) == 0) {
                    session->data->timeout=30;
                } else {
                    session->data->timeout=300;
                }
                rcu_read_unlock_bh();
            } else {
                rcu_read_unlock_bh();
                session = create_nat_session(ip->protocol, ip->saddr, 0, ip->daddr, 0, nat_addr);
                if (session == NULL) {
                    return NF_DROP;
                }
                csum_replace4(&ip->check, ip->saddr, session->addr);
                ip->saddr = session->addr;
                rcu_read_unlock_bh();
            }
        }
    } else if (info->variant == XTNAT_DNAT) {
        if (ip->protocol == IPPROTO_TCP) {
            if (unlikely(skb->len < ip_hdrlen(skb) + sizeof(struct tcphdr))) {
                printk(KERN_DEBUG "xt_NAT DNAT: Drop truncated TCP packet\n");
                return NF_DROP;
            }
            skb_set_transport_header(skb, ip->ihl * 4);
            tcp = (struct tcphdr *)skb_transport_header(skb);
            skb_reset_transport_header(skb);

            if (unlikely(skb_shinfo(skb)->nr_frags > 1 && skb_headlen(skb) == sizeof(struct iphdr))) {
                frag = &skb_shinfo(skb)->frags[0];
                if (unlikely(skb_frag_size(frag) < sizeof(struct tcphdr))) {
                        printk(KERN_DEBUG "xt_NAT DNAT: drop TCP frag_size = %d\n", skb_frag_size(frag));
                        return NF_DROP;
                }
                tcp = (struct tcphdr *)skb_frag_address_safe(frag);
                if (unlikely(tcp == NULL)) {
                        printk(KERN_DEBUG "xt_NAT DNAT: drop fragmented TCP\n");
                        return NF_DROP;
                }
                atomic64_inc(&frags);
            }

            rcu_read_lock_bh();
            session = lookup_session(ht_outer, ip->protocol, ip->daddr, tcp->dest);
            if (likely(session)) {
		skb_reset_transport_header(skb);
                csum_replace4(&ip->check, ip->daddr, session->data->in_addr);
                inet_proto_csum_replace4(&tcp->check, skb, ip->daddr, session->data->in_addr, true);
                inet_proto_csum_replace2(&tcp->check, skb, tcp->dest, session->data->in_port, true);
                ip->daddr = session->data->in_addr;
                tcp->dest = session->data->in_port;
                if (tcp->fin || tcp->rst) {
                    session->data->timeout=10;
                    session->data->flags |= FLAG_TCP_FIN;
                } else if (session->data->flags & FLAG_TCP_FIN) {
                    session->data->timeout=10;
                    session->data->flags &= ~FLAG_TCP_FIN;
                } else if ((session->data->flags & FLAG_REPLIED) == 0) {
                    session->data->timeout=300;
                    session->data->flags |= FLAG_REPLIED;
                }
                rcu_read_unlock_bh();
            } else {
                rcu_read_unlock_bh();
                atomic64_inc(&dnat_dropped);
            }
        } else if (ip->protocol == IPPROTO_UDP) {
            if (unlikely(skb->len < ip_hdrlen(skb) + sizeof(struct udphdr))) {
                printk(KERN_DEBUG "xt_NAT DNAT: Drop truncated UDP packet\n");
                return NF_DROP;
            }

            skb_set_transport_header(skb, ip->ihl * 4);
            udp = (struct udphdr *)skb_transport_header(skb);

            if (unlikely(skb_shinfo(skb)->nr_frags > 1 && skb_headlen(skb) == sizeof(struct iphdr))) {
                frag = &skb_shinfo(skb)->frags[0];
                if (unlikely(skb_frag_size(frag) < sizeof(struct udphdr))) {
                        printk(KERN_DEBUG "xt_NAT DNAT: drop UDP frag_size = %d\n", skb_frag_size(frag));
                        return NF_DROP;
                }
                udp = (struct udphdr *)skb_frag_address_safe(frag);
                if (unlikely(udp == NULL)) {
                        printk(KERN_DEBUG "xt_NAT DNAT: drop fragmented UDP\n");
                        return NF_DROP;
                }
                atomic64_inc(&frags);
            }

            rcu_read_lock_bh();
            session = lookup_session(ht_outer, ip->protocol, ip->daddr, udp->dest);
            if (likely(session)) {
		skb_reset_transport_header(skb);
                csum_replace4(&ip->check, ip->daddr, session->data->in_addr);
                if (udp->check) {
                    inet_proto_csum_replace4(&udp->check, skb, ip->daddr, session->data->in_addr, true);
                    inet_proto_csum_replace2(&udp->check, skb, udp->dest, session->data->in_port, true);
                }
                ip->daddr = session->data->in_addr;
                udp->dest = session->data->in_port;

                if ((session->data->flags & FLAG_REPLIED) == 0) {
                    session->data->timeout=300;
                    session->data->flags |= FLAG_REPLIED;
                }
                rcu_read_unlock_bh();
            } else {
                rcu_read_unlock_bh();
                atomic64_inc(&dnat_dropped);
            }
        } else if (ip->protocol == IPPROTO_ICMP) {
            if (unlikely(skb->len < ip_hdrlen(skb) + sizeof(struct icmphdr))) {
                printk(KERN_DEBUG "xt_NAT DNAT: Drop truncated ICMP packet\n");
                return NF_DROP;
            }

            skb_set_transport_header(skb, ip->ihl * 4);
            icmp = (struct icmphdr *)skb_transport_header(skb);

            nat_port = 0;
            if (icmp->type == 0 || icmp->type == 8) {
                nat_port = icmp->un.echo.id;
            } else if (icmp->type == 3 || icmp->type == 4 || icmp->type == 5 || icmp->type == 11 || icmp->type == 12 || icmp->type == 31) {
                atomic64_inc(&related_icmp);
                if (skb->len < ip_hdrlen(skb) + sizeof(struct icmphdr) + sizeof(struct iphdr)) {
                    printk(KERN_DEBUG "xt_NAT DNAT: Drop related ICMP packet witch truncated IP header\n");
                    return NF_DROP;
                }

                skb_set_network_header(skb,sizeof(struct icmphdr) + sizeof(struct iphdr));
                ip = (struct iphdr *)skb_network_header(skb);
                skb_reset_network_header(skb);

                if (ip->protocol == IPPROTO_TCP) {
                    if (skb->len < ip_hdrlen(skb) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8) {
                        printk(KERN_DEBUG "xt_NAT DNAT: Drop related ICMP packet witch truncated TCP header\n");
                        return NF_DROP;
                    }
                    skb_set_transport_header(skb, (ip->ihl * 4) + sizeof(struct icmphdr) + sizeof(struct iphdr));
                    tcp = (struct tcphdr *)skb_transport_header(skb);
                    skb_reset_transport_header(skb);
                    rcu_read_lock_bh();
                    session = lookup_session(ht_outer, ip->protocol, ip->saddr, tcp->source);
                    if (session) {
                        csum_replace4(&ip->check, ip->saddr, session->data->in_addr);
                        ip->saddr = session->data->in_addr;
                        tcp->source = session->data->in_port;
                    } else {
                        rcu_read_unlock_bh();
                        return NF_ACCEPT;
                    }

                    ip = (struct iphdr *)skb_network_header(skb);
                    csum_replace4(&ip->check, ip->daddr, session->data->in_addr);
                    ip->daddr = session->data->in_addr;
                    rcu_read_unlock_bh();
                } else if (ip->protocol == IPPROTO_UDP) {
                    if (skb->len < ip_hdrlen(skb) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8) {
                        printk(KERN_DEBUG "xt_NAT DNAT: Drop related ICMP packet witch truncated UDP header\n");
                        return NF_DROP;
                    }

                    skb_set_transport_header(skb, (ip->ihl * 4) + sizeof(struct icmphdr) + sizeof(struct iphdr));
                    udp = (struct udphdr *)skb_transport_header(skb);
                    skb_reset_transport_header(skb);
                    rcu_read_lock_bh();
                    session = lookup_session(ht_outer, ip->protocol, ip->saddr, udp->source);
                    if (session) {
                        csum_replace4(&ip->check, ip->saddr, session->data->in_addr);
                        ip->saddr = session->data->in_addr;
                        udp->source = session->data->in_port;
                    } else {
                        rcu_read_unlock_bh();
                        return NF_ACCEPT;
                    }
                    ip = (struct iphdr *)skb_network_header(skb);

                    csum_replace4(&ip->check, ip->daddr, session->data->in_addr);
                    ip->daddr = session->data->in_addr;
                    rcu_read_unlock_bh();
                } else if (ip->protocol == IPPROTO_ICMP) {
                    if (skb->len < ip_hdrlen(skb) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8) {
                        printk(KERN_DEBUG "xt_NAT DNAT: Drop related ICMP packet witch truncated ICMP header\n");
                        return NF_DROP;
                    }

                    skb_set_transport_header(skb, (ip->ihl * 4) + sizeof(struct icmphdr) + sizeof(struct iphdr));
                    icmp = (struct icmphdr *)skb_transport_header(skb);
                    skb_reset_transport_header(skb);

                    nat_port = 0;
                    if (icmp->type == 0 || icmp->type == 8) {
                        nat_port = icmp->un.echo.id;
                    }

                    rcu_read_lock_bh();
                    session = lookup_session(ht_outer, ip->protocol, ip->saddr, nat_port);
                    if (session) {
                        csum_replace4(&ip->check, ip->saddr, session->data->in_addr);
                        ip->saddr = session->data->in_addr;

                        if (icmp->type == 0 || icmp->type == 8) {
                            inet_proto_csum_replace2(&icmp->checksum, skb, nat_port, session->data->in_port, true);
                            icmp->un.echo.id = session->data->in_port;
                        }

                    } else {
                        rcu_read_unlock_bh();
                        return NF_ACCEPT;
                    }
                    ip = (struct iphdr *)skb_network_header(skb);
                    csum_replace4(&ip->check, ip->daddr, session->data->in_addr);
                    ip->daddr = session->data->in_addr;
                    rcu_read_unlock_bh();
                }
                return NF_ACCEPT;
            }
            rcu_read_lock_bh();
            session = lookup_session(ht_outer, ip->protocol, ip->daddr, nat_port);
            if (likely(session)) {
                csum_replace4(&ip->check, ip->daddr, session->data->in_addr);
                ip->daddr = session->data->in_addr;
                if (icmp->type == 0 || icmp->type == 8) {
                    inet_proto_csum_replace2(&icmp->checksum, skb, nat_port, session->data->in_port, true);
                    icmp->un.echo.id = session->data->in_port;
                }
                if ((session->data->flags & FLAG_REPLIED) == 0) {
                    session->data->timeout=30;
                    session->data->flags |= FLAG_REPLIED;
                }
                rcu_read_unlock_bh();
            } else {
                rcu_read_unlock_bh();
                atomic64_inc(&dnat_dropped);
            }
        } else {
            nat_port = 0;
            rcu_read_lock_bh();
            session = lookup_session(ht_outer, ip->protocol, ip->daddr, nat_port);
            if (likely(session)) {
                csum_replace4(&ip->check, ip->daddr, session->data->in_addr);
                ip->daddr = session->data->in_addr;
                if ((session->data->flags & FLAG_REPLIED) == 0) {
                    session->data->timeout=300;
                    session->data->flags |= FLAG_REPLIED;
                }
                rcu_read_unlock_bh();
            } else {
                rcu_read_unlock_bh();
                atomic64_inc(&dnat_dropped);
            }
        }
    }
    return NF_ACCEPT;
}

void users_cleanup_timer_callback( struct timer_list *timer )
{
    struct user_htable_ent *user;
    struct hlist_head *head;
    struct hlist_node *next;
    unsigned int i;
    u_int32_t vector_start, vector_end;

    spin_lock_bh(&users_timer_lock);

    if (ht_users == NULL) {
        printk(KERN_WARNING "xt_NAT USERS CLEAN ERROR: Found null ptr for ht_users\n");
        spin_unlock_bh(&users_timer_lock);
        return;
    }

    vector_start = users_htable_vector * (users_hash_size/60);
    if (users_htable_vector == 60) {
        vector_end = users_hash_size;
        users_htable_vector = 0;
    } else {
        vector_end = vector_start + (users_hash_size/60);
        users_htable_vector++;
    }

    for (i = vector_start; i < vector_end; i++) {
        spin_lock_bh(&ht_users[i].lock);
        if (ht_users[i].use > 0) {
            head = &ht_users[i].user;
            hlist_for_each_entry_safe(user, next, head, list_node) {
                if (user->tcp_count == 0 && user->udp_count == 0 && user->other_count == 0) {
                    user->idle++;
                }
                if (user->idle > 15) {
                    hlist_del_rcu(&user->list_node);
                    ht_users[i].use--;
                    kfree_rcu(user, rcu);
                    atomic64_dec(&users_active);
                }
            }
        }
        spin_unlock_bh(&ht_users[i].lock);
    }
    mod_timer( &users_cleanup_timer, jiffies + msecs_to_jiffies(1000) );
    spin_unlock_bh(&users_timer_lock);
}

void sessions_cleanup_timer_callback( struct timer_list *timer )
{
    struct nat_htable_ent *session;
    struct hlist_head *head;
    struct hlist_node *next;
    unsigned int i;
    void *p;
    u_int32_t vector_start, vector_end;

    spin_lock_bh(&sessions_timer_lock);

    if (ht_inner == NULL || ht_outer == NULL) {
        printk(KERN_WARNING "xt_NAT SESSIONS CLEAN ERROR: Found null ptr for ht_inner/ht_outer\n");
        spin_unlock_bh(&sessions_timer_lock);
        return;
    }

    vector_start = nat_htable_vector * (nat_hash_size/100);
    if (nat_htable_vector == 100) {
        vector_end = nat_hash_size;
        nat_htable_vector = 0;
    } else {
        vector_end = vector_start + (nat_hash_size/100);
        nat_htable_vector++;
    }

    for (i = vector_start; i < vector_end; i++) {
        spin_lock_bh(&ht_inner[i].lock);
        if (ht_inner[i].use > 0) {
            head = &ht_inner[i].session;
            hlist_for_each_entry_safe(session, next, head, list_node) {
                session->data->timeout -= 10;
                if (session->data->timeout == 0) {
                    netflow_export_flow_v9(session->proto, session->addr, session->port, session->data->dst_addr, session->data->dst_port, get_nat_addr(session->addr), session->data->out_port, 2);
                } else if (session->data->timeout <= -10) {
                    hlist_del_rcu(&session->list_node);
                    ht_inner[i].use--;
                    kfree_rcu(session, rcu);
                    update_user_limits(session->proto, session->addr, -1);
                }
            }
        }
        spin_unlock_bh(&ht_inner[i].lock);
    }

    for (i = vector_start; i < vector_end; i++) {
        spin_lock_bh(&ht_outer[i].lock);
        if (ht_outer[i].use > 0) {
            head = &ht_outer[i].session;
            hlist_for_each_entry_safe(session, next, head, list_node) {
                if (session->data->timeout <= -10) {
                    hlist_del_rcu(&session->list_node);
                    ht_outer[i].use--;
                    p = session->data;
                    kfree_rcu(session, rcu);
                    kfree(p);
                    atomic64_dec(&sessions_active);
                }
            }
        }
        spin_unlock_bh(&ht_outer[i].lock);
    }

    mod_timer( &sessions_cleanup_timer, jiffies + msecs_to_jiffies(100) );
    spin_unlock_bh(&sessions_timer_lock);
}

void nf_send_timer_callback( struct timer_list *timer )
{
    spin_lock_bh(&nfsend_lock);
    netflow_export_pdu_v9();
    mod_timer( &nf_send_timer, jiffies + msecs_to_jiffies(1000) );
    spin_unlock_bh(&nfsend_lock);
}

static int nat_seq_show(struct seq_file *m, void *v)
{
    struct nat_htable_ent *session;
    struct hlist_head *head;
    unsigned int i, count;

    count=0;

    seq_printf(m, "Proto SrcIP:SrcPort -> NatIP:NatPort\n");
    for (i = 0; i < nat_hash_size; i++) {
        rcu_read_lock_bh();
        if (ht_outer[i].use > 0) {
            head = &ht_outer[i].session;
            hlist_for_each_entry_rcu(session, head, list_node) {
                if (session->data->timeout > 0) {
                    seq_printf(m, "%d %pI4:%u -> %pI4:%u --- ttl: %d\n",
                               session->proto,
                               &session->data->in_addr, ntohs(session->data->in_port),
                               &session->addr, ntohs(session->port),
                               session->data->timeout);
                } else {
                    seq_printf(m, "%d %pI4:%u -> %pI4:%u --- (will be removed due timeout)\n",
                               session->proto,
                               &session->data->in_addr, ntohs(session->data->in_port),
                               &session->addr, ntohs(session->port));
                }
                count++;
            }
        }
        rcu_read_unlock_bh();
    }

    seq_printf(m, "Total translations: %d\n", count);

    return 0;
}
static int nat_seq_open(struct inode *inode, struct file *file)
{
    return single_open(file, nat_seq_show, NULL);
}
static const struct proc_ops nat_seq_fops = {
    .proc_open		= nat_seq_open,
    .proc_read		= seq_read,
    .proc_lseek		= seq_lseek,
    .proc_release	= single_release,
};


static int users_seq_show(struct seq_file *m, void *v)
{
    struct user_htable_ent *user;
    struct hlist_head *head;
    u_int32_t nataddr;
    unsigned int i, count;

    count=0;

    for (i = 0; i < users_hash_size; i++) {
        rcu_read_lock_bh();
        if (ht_users[i].use > 0) {
            head = &ht_users[i].user;
            hlist_for_each_entry_rcu(user, head, list_node) {
                if (user->idle < 15) {
                    nataddr = get_nat_addr(user->addr);
                    seq_printf(m, "%pI4 -> %pI4 (tcp: %u, udp: %u, other: %u)\n",
                               &user->addr,
                               &nataddr,
                               user->tcp_count,
                               user->udp_count,
                               user->other_count);
                    count++;
                }
            }
        }
        rcu_read_unlock_bh();
    }

    seq_printf(m, "Total users: %d\n", count);

    return 0;
}
static int users_seq_open(struct inode *inode, struct file *file)
{
    return single_open(file, users_seq_show, NULL);
}
static const struct proc_ops users_seq_fops = {
    .proc_open           = users_seq_open,
    .proc_read           = seq_read,
    .proc_lseek          = seq_lseek,
    .proc_release        = single_release,
};

static int stat_seq_show(struct seq_file *m, void *v)
{
    seq_printf(m, "Active NAT sessions: %lld\n", atomic64_read(&sessions_active));
    seq_printf(m, "Tried NAT sessions: %lld\n", atomic64_read(&sessions_tried));
    seq_printf(m, "Created NAT sessions: %lld\n", atomic64_read(&sessions_created));
    seq_printf(m, "DNAT dropped pkts: %lld\n", atomic64_read(&dnat_dropped));
    seq_printf(m, "Fragmented pkts: %lld\n", atomic64_read(&frags));
    seq_printf(m, "Related ICMP pkts: %lld\n", atomic64_read(&related_icmp));
    seq_printf(m, "Active Users: %lld\n", atomic64_read(&users_active));

    return 0;
}
static int stat_seq_open(struct inode *inode, struct file *file)
{
    return single_open(file, stat_seq_show, NULL);
}
static const struct proc_ops stat_seq_fops = {
    .proc_open           = stat_seq_open,
    .proc_read           = seq_read,
    .proc_lseek          = seq_lseek,
    .proc_release        = single_release,
};

#define SEPARATORS " ,;\t\n"
static int add_nf_destinations(const char *ptr)
{
    int len;

    for (; ptr; ptr += len) {
        struct sockaddr_storage ss;
        struct netflow_sock *usock;
        struct sockaddr_in *sin;
        const char *end;
        int succ = 0;

        /* skip initial separators */
        ptr += strspn(ptr, SEPARATORS);

        len = strcspn(ptr, SEPARATORS);
        if (!len)
            break;
        memset(&ss, 0, sizeof(ss));

        sin = (struct sockaddr_in *)&ss;

        sin->sin_family = AF_INET;
        sin->sin_port = htons(2055);
        succ = in4_pton(ptr, len, (u8 *)&sin->sin_addr, -1, &end);
        if (succ && *end == ':')
            sin->sin_port = htons(simple_strtoul(++end, NULL, 0));

        if (!succ) {
            printk(KERN_ERR "xt_NAT: can't parse netflow destination: %.*s\n",
                   len, ptr);
            continue;
        }

        if (!(usock = vmalloc(sizeof(*usock)))) {
            printk(KERN_ERR "xt_NAT: can't vmalloc socket\n");
            return -ENOMEM;
        }
        memset(usock, 0, sizeof(*usock));
        usock->addr = ss;
        list_add_tail(&usock->list, &usock_list);
        printk(KERN_INFO "xt_NAT NEL: add destination %s\n", print_sockaddr(&usock->addr));
    }
    return 0;
}

static struct xt_target nat_tg_reg __read_mostly = {
    .name     = "NAT",
    .revision = 0,
    .family   = NFPROTO_IPV4,
    .hooks    = (1 << NF_INET_FORWARD) | (1 << NF_INET_PRE_ROUTING) | (1 << NF_INET_POST_ROUTING),
    .target   = nat_tg,
    .targetsize = sizeof(struct xt_nat_tginfo),
    .me       = THIS_MODULE,
};

static int __init nat_tg_init(void)
{
    char buff[128] = { 0 };
    int i, j;

    printk(KERN_INFO "Module xt_NAT loaded\n");

    templateV9.FlowSetId	= 0;
    templateV9.Length		= htons(40);
    templateV9.TemplateId	= htons(flowsetID);
    templateV9.FieldsCount	= htons(8);
    templateV9.proto_id		= htons(4);
    templateV9.proto_len	= htons(1);
    templateV9.s_port_id	= htons(7);
    templateV9.s_port_len	= htons(2);
    templateV9.s_addr_id	= htons(8);
    templateV9.s_addr_len	= htons(4);
    templateV9.d_port_id	= htons(11);
    templateV9.d_port_len	= htons(2);
    templateV9.d_addr_id	= htons(12);
    templateV9.d_addr_len	= htons(4);
    templateV9.n_addr_id	= htons(225);
    templateV9.n_addr_len	= htons(4);
    templateV9.n_port_id	= htons(227);
    templateV9.n_port_len	= htons(2);
    templateV9.s_type_id	= htons(230);
    templateV9.s_type_len	= htons(1);

    for(i=0, j=0; i<128 && nat_pool[i] != '-' && nat_pool[i] != '\0'; i++, j++) {
        buff[j] = nat_pool[i];
    }
    nat_pool_start = in_aton(buff);

    for(i++, j=0; i<128 && nat_pool[i] != '-' && nat_pool[i] != '\0'; i++, j++) {
        buff[j] = nat_pool[i];
    }
    nat_pool_end = in_aton(buff);

    if (nat_pool_start && nat_pool_end && nat_pool_start <= nat_pool_end ) {
        printk(KERN_INFO "xt_NAT DEBUG: IP Pool from %pI4 to %pI4\n", &nat_pool_start, &nat_pool_end);
        pool_table_create();
    } else {
        printk(KERN_INFO "xt_NAT DEBUG: BAD IP Pool from %pI4 to %pI4\n", &nat_pool_start, &nat_pool_end);
        return -1;
    }

    printk(KERN_INFO "xt_NAT DEBUG: NAT hash size: %d\n", nat_hash_size);
    printk(KERN_INFO "xt_NAT DEBUG: Users hash size: %d\n", users_hash_size);

    nat_htable_create();
    users_htable_create();
    pool_table_create();

    add_nf_destinations(nf_dest);

    proc_net_nat = proc_mkdir("NAT",init_net.proc_net);
    proc_create("sessions", 0644, proc_net_nat, &nat_seq_fops);
    proc_create("users", 0644, proc_net_nat, &users_seq_fops);
    proc_create("statistics", 0644, proc_net_nat, &stat_seq_fops);

    spin_lock_bh(&sessions_timer_lock);
    timer_setup( &sessions_cleanup_timer, sessions_cleanup_timer_callback, 0 );
    mod_timer( &sessions_cleanup_timer, jiffies + msecs_to_jiffies(10 * 1000) );
    spin_unlock_bh(&sessions_timer_lock);

    spin_lock_bh(&users_timer_lock);
    timer_setup( &users_cleanup_timer, users_cleanup_timer_callback, 0 );
    mod_timer( &users_cleanup_timer, jiffies + msecs_to_jiffies(60 * 1000) );
    spin_unlock_bh(&users_timer_lock);

    spin_lock_bh(&nfsend_lock);
    timer_setup( &nf_send_timer, nf_send_timer_callback, 0 );
    mod_timer( &nf_send_timer, jiffies + msecs_to_jiffies(1000) );
    spin_unlock_bh(&nfsend_lock);

    return xt_register_target(&nat_tg_reg);
}

static void __exit nat_tg_exit(void)
{
    xt_unregister_target(&nat_tg_reg);

    spin_lock_bh(&sessions_timer_lock);
    spin_lock_bh(&users_timer_lock);
    spin_lock_bh(&nfsend_lock);
    del_timer( &sessions_cleanup_timer );
    del_timer( &users_cleanup_timer );
    del_timer( &nf_send_timer );

    remove_proc_entry( "sessions", proc_net_nat );
    remove_proc_entry( "users", proc_net_nat );
    remove_proc_entry( "statistics", proc_net_nat );
    proc_remove(proc_net_nat);

    pool_table_remove();
    users_htable_remove();
    nat_htable_remove();

    while (!list_empty(&usock_list)) {
        struct netflow_sock *usock;

        usock = list_entry(usock_list.next, struct netflow_sock, list);
        list_del(&usock->list);
        if (usock->sock)
            sock_release(usock->sock);
        usock->sock = NULL;
        vfree(usock);
    }

    spin_unlock_bh(&sessions_timer_lock);
    spin_unlock_bh(&users_timer_lock);
    spin_unlock_bh(&nfsend_lock);

    printk(KERN_INFO "Module xt_NAT unloaded\n");
}

module_init(nat_tg_init);
module_exit(nat_tg_exit);

MODULE_DESCRIPTION("Xtables: Full Cone NAT");
MODULE_AUTHOR("Andrei Sharaev <andr.sharaev@gmail.com>");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_NAT");

