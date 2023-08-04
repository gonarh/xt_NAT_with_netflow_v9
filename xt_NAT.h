#ifndef _LINUX_NETFILTER_XT_NAT_H
#define _LINUX_NETFILTER_XT_NAT_H 1

enum xt_nat_target_variant {
    XTNAT_SNAT,
    XTNAT_DNAT,
};

struct xt_nat_tginfo {
    uint8_t variant;
};

#define NETFLOW9_RECORDS_MAX 30

struct netflow9_record {
    __u8	protocol;
    __be16	s_port;
    __be32	s_addr;
    __be16	d_port;
    __be32	d_addr;
    __be32	n_addr;
    __be16	n_port;
    __u8	event;
} __attribute__ ((packed));

/* NetFlow v9 template */
struct netflow9_template {
    __be16	FlowSetId;
    __be16	Length;
    __be16	TemplateId;
    __be16	FieldsCount;
    __be16	proto_id;
    __be16	proto_len;
    __be16	s_port_id;
    __be16	s_port_len;
    __be16	s_addr_id;
    __be16	s_addr_len;
    __be16	d_port_id;
    __be16	d_port_len;
    __be16	d_addr_id;
    __be16	d_addr_len;
    __be16	n_addr_id;
    __be16	n_addr_len;
    __be16	n_port_id;
    __be16	n_port_len;
    __be16	s_type_id;
    __be16	s_type_len;
} __attribute__ ((packed));

/* NetFlow v9 packet */
struct netflow9_pdu {
    __be16	version;
    __be16	nr_records;
    __be32	ts_uptime; /* ms */
    __be32	ts_usecs;  /* s  */
    __be32	seq;
    __be32	srcID;
    struct netflow9_template template_V9;
    __be16	FlowSetId;
    __be16	FlowSetIdSize;
    struct netflow9_record flow[NETFLOW9_RECORDS_MAX];
} __attribute__ ((packed));

#define NETFLOW9_HEADER_SIZE (sizeof(struct netflow9_pdu) - NETFLOW9_RECORDS_MAX * sizeof(struct netflow9_record))

#endif /* _LINUX_NETFILTER_XT_NAT_H */
