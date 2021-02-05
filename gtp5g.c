/* SPDX-License-Identifier: GPL-2.0-or-later */
/* GTP5G according to 3GPP TS 29.281 / 3GPP TS 29.244
 *
 * Author: Yao-Wen Chang <yaowenowo@gmail.com>
 *		Muthuraman Elangovan <muthuramane.cs03g@g2.nctu.edu.tw>
 *	   	Chi Chang <edingroot@gmail.com>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/rculist.h>
#include <linux/jhash.h>
#include <linux/if_tunnel.h>
#include <linux/net.h>
#include <linux/file.h>
#include <linux/gtp.h>
#include <linux/range.h>
#include <linux/un.h>

#include <net/net_namespace.h>
#include <net/protocol.h>
#include <net/ip.h>
#include <net/udp.h>
#include <net/udp_tunnel.h>
#include <net/icmp.h>
#include <net/xfrm.h>
#include <net/genetlink.h>
#include <net/netns/generic.h>

#include "gtp5g.h"

#define DRV_VERSION "1.0.0-f"

struct local_f_teid {
    u32     teid;                       // i_teid
    struct in_addr gtpu_addr_ipv4;      // self upf ip
};

struct ip_filter_rule {
    uint8_t action;                     // permit only
    uint8_t direction;                  // in/out
    uint8_t proto;                      // number or "ip" which is not used for matching
    struct in_addr src, smask;          // ip addr or "any" -> 0.0.0.0
    struct in_addr dest, dmask;         // ip addr or "any" -> 0.0.0.0
    int sport_num;                      // Conut for sport
    struct range *sport;                // one value, range or not existed -> [0, 0]
    int dport_num;                      // Counter for dport
    struct range *dport;                // one value, range or not existed -> [0, 0]
};

struct gtp5g_qer {
    struct hlist_node    hlist_id;

    u32 id;								/* 8.2.75 QER_ID */
	uint8_t     ul_dl_gate;             /* 8.2.7 Gate Status */
    struct {
        uint32_t    ul_high;
        uint8_t     ul_low;
        uint32_t    dl_high;
        uint8_t     dl_low;
    } mbr;                              /* 8.2.8 MBR */
    struct {
        uint32_t    ul_high;
        uint8_t     ul_low;
        uint32_t    dl_high;
        uint8_t     dl_low;
    } gbr;                              /* 8.2.9 GBR */
    uint32_t        qer_corr_id;        /* 8.2.10 QER Correlation ID  */
    uint8_t         rqi;                /* 8.2.88 RQI */
    uint8_t         qfi;                /* 8.2.89 QFI */

    /* 8.2.115 Averaging Window (Optional) */

    uint8_t         ppi;                /* 8.2.116 Paging Policy Indicator */

    /* 8.2.139 Packet Rate Status */

    /* Rate Control Status Reporting */
    uint8_t         rcsr;               /* 8.2.174 QER Control Indications */

    struct net_device   *dev;
    struct rcu_head     rcu_head;
};

struct sdf_filter {
    struct ip_filter_rule *rule;
    uint16_t *tos_traffic_class;
    u32 *security_param_idx;
    u32 *flow_label;               // exactly 3 Octets
    u32 *bi_id;
};

struct gtp5g_pdi {
//    u8      src_iface;                // 0: Access, 1: Core, 2: SGi-LAN/N6-LAN, 3: CP-function
    struct in_addr *ue_addr_ipv4;
//  char *network_instance
    struct local_f_teid *f_teid;
    struct sdf_filter *sdf;
};

struct outer_header_creation {
    u16    description;
    u32    teid;                        // o_teid
    struct in_addr peer_addr_ipv4;
    u16 port;
};

struct forwarding_policy {
    int len;
    char identifier[0xff + 1];

    /* Exact value to handle forwarding policy */
    u32 mark;
};

struct forwarding_parameter {
	//uint8_t dest_int;
	//char *network_instance;

    struct outer_header_creation *hdr_creation;
    struct forwarding_policy *fwd_policy;
};

struct gtp5g_far {
    struct hlist_node    hlist_id;

    u32 id;

	//u8 dest_iface;
    u8 action;                              // apply action

    struct forwarding_parameter *fwd_param;

    struct net_device   *dev;
    struct rcu_head     rcu_head;
};

struct gtp5g_pdr {
    struct hlist_node    	hlist_id;
    struct hlist_node    	hlist_i_teid;
    struct hlist_node    	hlist_addr;
    struct hlist_node    	hlist_related_far;
    struct hlist_node    	hlist_related_qer;

    u16     				id;
    u32     				precedence;
    u8      				*outer_header_removal;

    struct gtp5g_pdi      	*pdi;

    u32     				*far_id;
    struct gtp5g_far      	*far;

    u32     				*qer_id;
    struct gtp5g_qer      	*qer;

    // AF_UNIX socket for buffer
    struct sockaddr_un 		addr_unix;
    struct socket 			*sock_for_buf;

    u16     af;
    struct in_addr 			role_addr_ipv4;
    struct sock            	*sk;
    struct net_device   	*dev;
    struct rcu_head        	rcu_head;
};

/* One instance of the GTP device. */
struct gtp5g_dev {
    struct list_head    	list;

    struct sock        		*sk1u;

    struct net_device    	*dev;

    unsigned int        	role;

    unsigned int        	hash_size;
    struct hlist_head    	*pdr_id_hash;
    struct hlist_head    	*far_id_hash;
    struct hlist_head    	*qer_id_hash;

    struct hlist_head    	*i_teid_hash;      // Used for GTP-U packet detect
    struct hlist_head    	*addr_hash;        // Used for IPv4 packet detect

    /* IEs list related to PDR */
    struct hlist_head    	*related_far_hash;     // PDR list waiting the FAR to handle
    struct hlist_head    	*related_qer_hash;     // PDR list waiting the QER to handle
};

static unsigned int gtp5g_net_id __read_mostly;

struct gtp5g_net {
    struct list_head gtp5g_dev_list;
};

static struct gtp5g_qer *gtp5g_find_qer(struct net *net, struct nlattr *nla[]);
static struct gtp5g_qer *qer_find_by_id(struct gtp5g_dev *gtp, u32 id);
static void qer_context_delete(struct gtp5g_qer *qer);

/* Function unix_sock_{...} are used to handle buffering */
// Send PDR ID, FAR action and buffered packet to user space
static int unix_sock_send(struct gtp5g_pdr *pdr, void *buf, u32 len)
{
    struct msghdr msg;
    struct iovec iov[2];
    mm_segment_t oldfs;

    int msg_iovlen = sizeof(iov) / sizeof(struct iovec);
    int total_iov_len = 0;
    int i, rt;
    u16 self_hdr[2] = {pdr->id, pdr->far->action};

    if (!pdr->sock_for_buf)
        return -EINVAL;

    memset(&msg, 0, sizeof(msg));
    memset(iov, 0, sizeof(iov));

    iov[0].iov_base = self_hdr;
    iov[0].iov_len = sizeof(self_hdr);
    iov[1].iov_base = buf;
    iov[1].iov_len = len;

    for (i = 0; i < msg_iovlen; i++)
        total_iov_len += iov[i].iov_len;

    msg.msg_name = 0;
    msg.msg_namelen = 0;
    iov_iter_init(&msg.msg_iter, WRITE, iov, msg_iovlen, total_iov_len);
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;

    oldfs = get_fs();
    set_fs(KERNEL_DS);
    rt = sock_sendmsg(pdr->sock_for_buf, &msg);
    set_fs(oldfs);

    return rt;
}

// Delete the AF_UNIX client
static void unix_sock_client_delete(struct gtp5g_pdr *pdr)
{
    if (pdr->sock_for_buf)
        sock_release(pdr->sock_for_buf);
    
    pdr->sock_for_buf = NULL;
}

// Create a AF_UNIX client by specific name sent from user space
static int unix_sock_client_new(struct gtp5g_pdr *pdr)
{
    int rt;
    struct socket **psock = &pdr->sock_for_buf;
    struct sockaddr_un *addr = &pdr->addr_unix;

    if (!strlen(addr->sun_path))
        return -EINVAL;

    rt = sock_create(AF_UNIX, SOCK_DGRAM, 0, psock);
    if (rt) {
        pr_err("Sock create fail\n");
        return rt;
    }

    rt = (*psock)->ops->connect(*psock, (struct sockaddr *) addr,
            sizeof(addr->sun_family) + strlen(addr->sun_path), 0);
    if (rt) {
        unix_sock_client_delete(pdr);
        pr_err("Unix sock connect fail\n");
        return rt;
    }

    return 0;
}

// Handle PDR/FAR changed and affect buffering
static int unix_sock_client_update(struct gtp5g_pdr *pdr)
{
    struct gtp5g_far *far = pdr->far;
    
    unix_sock_client_delete(pdr);
    
    if (far && (far->action & FAR_ACTION_BUFF))
        return unix_sock_client_new(pdr);

    return 0;
}

static u32 gtp5g_h_initval;

static inline u32 u32_hashfn(u32 val)
{
    return jhash_1word(val, gtp5g_h_initval);
}

static inline u32 ipv4_hashfn(__be32 ip)
{
    return jhash_1word((__force u32)ip, gtp5g_h_initval);
}

static struct gtp5g_far *far_find_by_id(struct gtp5g_dev *gtp, u32 id)
{
    struct hlist_head *head;
    struct gtp5g_far *far;

    head = &gtp->far_id_hash[u32_hashfn(id) % gtp->hash_size];

    hlist_for_each_entry_rcu(far, head, hlist_id) {
        if (far->id == id)
            return far;
    }

    return NULL;
}

static int far_fill(struct gtp5g_far *far, struct gtp5g_dev *gtp, struct genl_info *info)
{
    struct nlattr *fwd_param_attrs[GTP5G_FORWARDING_PARAMETER_ATTR_MAX + 1];
    struct nlattr *hdr_creation_attrs[GTP5G_OUTER_HEADER_CREATION_ATTR_MAX + 1];
    struct outer_header_creation *hdr_creation;
    struct forwarding_policy *fwd_policy;

    // Update related PDR for buffering
    struct gtp5g_pdr *pdr;
    struct hlist_head *head;

    if (!far)
        return -EINVAL;

    far->id = nla_get_u32(info->attrs[GTP5G_FAR_ID]);

    if (info->attrs[GTP5G_FAR_APPLY_ACTION]) {
        far->action = nla_get_u8(info->attrs[GTP5G_FAR_APPLY_ACTION]);
    }

    if (info->attrs[GTP5G_FAR_FORWARDING_PARAMETER] &&
        !nla_parse_nested(fwd_param_attrs, 
						GTP5G_FORWARDING_PARAMETER_ATTR_MAX, 
						info->attrs[GTP5G_FAR_FORWARDING_PARAMETER], 
						NULL, 
						NULL)) {
        if (!far->fwd_param) {
            far->fwd_param = kzalloc(sizeof(*far->fwd_param), GFP_ATOMIC);
            if (!far->fwd_param) {
				printk_ratelimited("%s:%d Failed to allocate FAR fwd param\n",
						__func__, __LINE__);
                return -ENOMEM;
			}
        }

        if (fwd_param_attrs[GTP5G_FORWARDING_PARAMETER_OUTER_HEADER_CREATION] &&
            !nla_parse_nested(hdr_creation_attrs, 
								GTP5G_OUTER_HEADER_CREATION_ATTR_MAX, 
								fwd_param_attrs[GTP5G_FORWARDING_PARAMETER_OUTER_HEADER_CREATION], 
								NULL, 
								NULL)) {
            if (!far->fwd_param->hdr_creation) {
                far->fwd_param->hdr_creation = kzalloc(sizeof(*far->fwd_param->hdr_creation), 
													GFP_ATOMIC);
                if (!far->fwd_param->hdr_creation) {
					printk_ratelimited("%s:%d Failed to allocate FAR fwd Hdr creation\n",
							__func__, __LINE__);
                    return -ENOMEM;
				}
            }
            hdr_creation = far->fwd_param->hdr_creation;

            if (!hdr_creation_attrs[GTP5G_OUTER_HEADER_CREATION_DESCRIPTION] ||
                !hdr_creation_attrs[GTP5G_OUTER_HEADER_CREATION_O_TEID] ||
                !hdr_creation_attrs[GTP5G_OUTER_HEADER_CREATION_PEER_ADDR_IPV4] ||
                !hdr_creation_attrs[GTP5G_OUTER_HEADER_CREATION_PORT])
                return -EINVAL;

            hdr_creation->description = nla_get_u16(hdr_creation_attrs[GTP5G_OUTER_HEADER_CREATION_DESCRIPTION]);
            hdr_creation->teid = htonl(nla_get_u32(hdr_creation_attrs[GTP5G_OUTER_HEADER_CREATION_O_TEID]));
            hdr_creation->peer_addr_ipv4.s_addr = nla_get_be32(hdr_creation_attrs[GTP5G_OUTER_HEADER_CREATION_PEER_ADDR_IPV4]);
            hdr_creation->port = htons(nla_get_u16(hdr_creation_attrs[GTP5G_OUTER_HEADER_CREATION_PORT]));
        }

        if (fwd_param_attrs[GTP5G_FORWARDING_PARAMETER_FORWARDING_POLICY]) {
            if (!far->fwd_param->fwd_policy) {
                far->fwd_param->fwd_policy = kzalloc(sizeof(*far->fwd_param->fwd_policy), 
													GFP_ATOMIC);
                if (!far->fwd_param->fwd_policy) {
					printk_ratelimited("%s:%d Failed to allocate FAR fwd policy\n",
							__func__, __LINE__);
                    return -ENOMEM;
				}
            }
            fwd_policy = far->fwd_param->fwd_policy;

            fwd_policy->len = nla_len(fwd_param_attrs[GTP5G_FORWARDING_PARAMETER_FORWARDING_POLICY]);
            if (fwd_policy->len >= sizeof(fwd_policy->identifier))
                return -EINVAL;
            strncpy(fwd_policy->identifier, nla_data(fwd_param_attrs[GTP5G_FORWARDING_PARAMETER_FORWARDING_POLICY]), fwd_policy->len);

            /* Exact value to handle forwarding policy */
            if (!(fwd_policy->mark = simple_strtol(fwd_policy->identifier, NULL, 10)))
                return -EINVAL;
        }
    }

    /* Update PDRs which has not linked to this FAR */
    head = &gtp->related_far_hash[u32_hashfn(far->id) % gtp->hash_size];
    hlist_for_each_entry_rcu(pdr, head, hlist_related_far) {
        if (*pdr->far_id == far->id) {
            pdr->far = far;
            if (unix_sock_client_update(pdr) < 0)
                pr_warn("PDR(%u) update fail when FAR(%u) apply action is changed",
                    pdr->id, far->id);
        }
    }

    return 0;
}

static struct gtp5g_pdr *pdr_find_by_id(struct gtp5g_dev *gtp, u16 id)
{
    struct hlist_head *head;
    struct gtp5g_pdr *pdr;

    head = &gtp->pdr_id_hash[u32_hashfn(id) % gtp->hash_size];
    hlist_for_each_entry_rcu(pdr, head, hlist_id) {
        if (pdr->id == id)
            return pdr;
    }

    return NULL;
}

static int ipv4_match(__be32 target_addr, __be32 ifa_addr, __be32 ifa_mask) {
    return !((target_addr ^ ifa_addr) & ifa_mask);
}

static int ports_match(struct range *match_list, int list_len, __be16 port) {
    int i;

    if (!list_len)
        return 1;

    for (i = 0; i < list_len; i++) {
        if (match_list[i].start <= port && match_list[i].end >= port)
            return 1;
    }
    return 0;
}

static int sdf_filter_match(struct sdf_filter *sdf, struct sk_buff *skb, unsigned int hdrlen, u8 direction)
{
    struct iphdr *iph;
    struct ip_filter_rule *rule;

    const __be16 *pptr;
	__be16 _ports[2];

    if (!sdf)
        return 1;

    if (!pskb_may_pull(skb, hdrlen + sizeof(struct iphdr)))
            goto MISMATCH;
 
    iph = (struct iphdr *)(skb->data + hdrlen);

    if (sdf->rule) {
        rule = sdf->rule;
        if (rule->direction != direction)
            goto MISMATCH;

        if (rule->proto != 0xff && rule->proto != iph->protocol)
            goto MISMATCH;

        if (!ipv4_match(iph->saddr, rule->src.s_addr, rule->smask.s_addr))
            goto MISMATCH;

        if (!ipv4_match(iph->daddr, rule->dest.s_addr, rule->dmask.s_addr))
            goto MISMATCH;
        
        if (rule->sport_num + rule->dport_num > 0) {
            if (!(pptr = skb_header_pointer(skb, hdrlen + sizeof(struct iphdr), sizeof(_ports), _ports)))
                goto MISMATCH;

            if (!ports_match(rule->sport, rule->sport_num, ntohs(pptr[0])))
                goto MISMATCH;
            
            if (!ports_match(rule->dport, rule->dport_num, ntohs(pptr[1])))
                goto MISMATCH;
        }
    }

    if (sdf->tos_traffic_class)
        pr_info("ToS traffic class check does not implement yet\n");
    
    if (sdf->security_param_idx)
        pr_info("Security parameter index check does not implement yet\n");

    if (sdf->flow_label)
        pr_info("Flow label check does not implement yet\n");

    if (sdf->bi_id)
        pr_info("SDF filter ID check does not implement yet\n");

    return 1;

MISMATCH:
    return 0;
}

static struct gtp5g_pdr *pdr_find_by_ipv4(struct gtp5g_dev *gtp, struct sk_buff *skb,
                                  unsigned int hdrlen, __be32 addr)
{
    struct hlist_head *head;
    struct gtp5g_pdr *pdr;
    struct gtp5g_pdi *pdi;

    head = &gtp->addr_hash[ipv4_hashfn(addr) % gtp->hash_size];

    hlist_for_each_entry_rcu(pdr, head, hlist_addr) {
        pdi = pdr->pdi;

        // TODO: Move the value we check into first level
        if (!(pdr->af == AF_INET && pdi->ue_addr_ipv4->s_addr == addr))
            continue;
        
        if (pdi->sdf)
            if (!sdf_filter_match(pdi->sdf, skb, hdrlen, GTP5G_SDF_FILTER_OUT))
                continue;

        return pdr;
    }

    return NULL;
}

static int pdr_fill(struct gtp5g_pdr *pdr, struct gtp5g_dev *gtp, struct genl_info *info)
{
    struct nlattr *pdi_attrs[GTP5G_PDI_ATTR_MAX + 1];
    struct nlattr *f_teid_attrs[GTP5G_F_TEID_ATTR_MAX + 1];
    struct nlattr *sdf_attrs[GTP5G_SDF_FILTER_ATTR_MAX + 1];
    struct nlattr *rule_attrs[GTP5G_FLOW_DESCRIPTION_ATTR_MAX + 1];
    struct hlist_head *head;
    struct gtp5g_pdr *ppdr, *last_ppdr;
    struct gtp5g_pdi *pdi = NULL;
    struct local_f_teid *f_teid = NULL;
    struct sdf_filter *sdf;
    struct ip_filter_rule *rule;
    int i;
    char *str;

    if (!pdr) {
        printk_ratelimited("%s:%d PDR is NULL\n", __func__, __LINE__);
		return -EINVAL;
	}

    pdr->af = AF_INET;
    pdr->id = nla_get_u16(info->attrs[GTP5G_PDR_ID]);

    if (info->attrs[GTP5G_PDR_PRECEDENCE]) 
        pdr->precedence = nla_get_u32(info->attrs[GTP5G_PDR_PRECEDENCE]);

    if (info->attrs[GTP5G_OUTER_HEADER_REMOVAL]) {
        if (!pdr->outer_header_removal) {
            pdr->outer_header_removal = kzalloc(sizeof(*pdr->outer_header_removal), GFP_ATOMIC);
            if (!pdr->outer_header_removal) {
				printk_ratelimited("%s:%d Failed to allocate OHC\n", __func__, __LINE__);
                return -ENOMEM;
			}
        }
        *pdr->outer_header_removal = nla_get_u8(info->attrs[GTP5G_OUTER_HEADER_REMOVAL]);
    }

    /* Not in 3GPP spec, just used for routing */
    if (info->attrs[GTP5G_PDR_ROLE_ADDR_IPV4])
        pdr->role_addr_ipv4.s_addr = nla_get_u32(info->attrs[GTP5G_PDR_ROLE_ADDR_IPV4]);

    /* Not in 3GPP spec, just used for buffering */
    if (info->attrs[GTP5G_PDR_UNIX_SOCKET_PATH]) {
        str = nla_data(info->attrs[GTP5G_PDR_UNIX_SOCKET_PATH]);
        pdr->addr_unix.sun_family = AF_UNIX;
        strncpy(pdr->addr_unix.sun_path, str, nla_len(info->attrs[GTP5G_PDR_UNIX_SOCKET_PATH]));
    }

	/* FAR */
    if (info->attrs[GTP5G_PDR_FAR_ID]) {
        if (!pdr->far_id) {
            pdr->far_id = kzalloc(sizeof(*pdr->far_id), GFP_ATOMIC);
            if (!pdr->far_id) {	
				printk_ratelimited("%s:%d Failed to allocate FAR\n", __func__, __LINE__);
                return -ENOMEM;
			}
        }
        *pdr->far_id = nla_get_u32(info->attrs[GTP5G_PDR_FAR_ID]);

        if (!hlist_unhashed(&pdr->hlist_related_far))
            hlist_del_rcu(&pdr->hlist_related_far);

        hlist_add_head_rcu(&pdr->hlist_related_far, 
							&gtp->related_far_hash[u32_hashfn(*pdr->far_id) % gtp->hash_size]);
        pdr->far = far_find_by_id(gtp, *pdr->far_id);
    } else {
		printk_ratelimited("%s:%d FAR ID not exist\n", __func__, __LINE__);
	}

	/* QER */
    if (info->attrs[GTP5G_PDR_QER_ID]) {
        if (!pdr->qer_id) {
            pdr->qer_id = kzalloc(sizeof(*pdr->qer_id), GFP_ATOMIC);
            if (!pdr->qer_id) {
            	printk_ratelimited("%s:%d Failed to allocate memory\n", __func__, __LINE__);
				return -ENOMEM;
			}
        }
        *pdr->qer_id = nla_get_u32(info->attrs[GTP5G_PDR_QER_ID]);

        if (!hlist_unhashed(&pdr->hlist_related_qer))
            hlist_del_rcu(&pdr->hlist_related_qer);

        hlist_add_head_rcu(&pdr->hlist_related_qer, 
							&gtp->related_qer_hash[u32_hashfn(*pdr->qer_id) % gtp->hash_size]);

        pdr->qer = qer_find_by_id(gtp, *pdr->qer_id);
		if (!pdr->qer)
			printk_ratelimited("%s:%d Failed to find QER id(%u)\n", __func__, __LINE__,
					*pdr->qer_id);
    } 

    if (unix_sock_client_update(pdr) < 0) {
		printk_ratelimited("%s:%d PDR sock client update fail\n", __func__, __LINE__);
        return -EINVAL;
	}

    /* Parse PDI in PDR */
    if (info->attrs[GTP5G_PDR_PDI] &&
        !nla_parse_nested(pdi_attrs, 
						GTP5G_PDI_ATTR_MAX, 
						info->attrs[GTP5G_PDR_PDI], 
						NULL, 
						NULL)) {
        if (!pdr->pdi) {
            pdr->pdi = kzalloc(sizeof(*pdr->pdi), GFP_ATOMIC);
            if (!pdr->pdi) {
				printk_ratelimited("%s:%d Failed to allocate PDI\n", __func__, __LINE__);
                return -ENOMEM;
			}
        }
        pdi = pdr->pdi;

        if (pdi_attrs[GTP5G_PDI_UE_ADDR_IPV4]) {
            if (!pdi->ue_addr_ipv4) {
                pdi->ue_addr_ipv4 = kzalloc(sizeof(*pdi->ue_addr_ipv4), GFP_ATOMIC);
                if (!pdi->ue_addr_ipv4) {
					printk_ratelimited("%s:%d Failed to allocate UE IPv4 address\n", __func__, __LINE__);
                    return -ENOMEM;
				}
            }

            pdi->ue_addr_ipv4->s_addr = nla_get_be32(pdi_attrs[GTP5G_PDI_UE_ADDR_IPV4]);
        }

        /* Parse F-TEID in PDI */
        if (pdi_attrs[GTP5G_PDI_F_TEID] &&
            !nla_parse_nested(f_teid_attrs, 
							GTP5G_F_TEID_ATTR_MAX, 
							pdi_attrs[GTP5G_PDI_F_TEID], 
							NULL, 
							NULL)) {
            if (!f_teid_attrs[GTP5G_F_TEID_I_TEID] || 
				!f_teid_attrs[GTP5G_F_TEID_GTPU_ADDR_IPV4]) {
				printk_ratelimited("%s:%d TEID is not preset\n", __func__, __LINE__);
                return -EINVAL;
			}

            if (!pdi->f_teid) {
                pdi->f_teid = kzalloc(sizeof(*pdi->f_teid), GFP_ATOMIC);
                if (!pdi->f_teid) {
					printk_ratelimited("%s:%d Failed to allocate UE IPv4 address\n", __func__, __LINE__);
                    return -ENOMEM;
				}
            }
            f_teid = pdi->f_teid;

            f_teid->teid = htonl(nla_get_u32(f_teid_attrs[GTP5G_F_TEID_I_TEID]));
            f_teid->gtpu_addr_ipv4.s_addr = nla_get_be32(f_teid_attrs[GTP5G_F_TEID_GTPU_ADDR_IPV4]);
        }

        /* Parse SDF Filter in PDI */
        if (pdi_attrs[GTP5G_PDI_SDF_FILTER] &&
            !nla_parse_nested(sdf_attrs, 
							GTP5G_SDF_FILTER_ATTR_MAX, 
							pdi_attrs[GTP5G_PDI_SDF_FILTER], 
							NULL, 
							NULL)) {
            if (!pdi->sdf) {
                pdi->sdf = kzalloc(sizeof(*pdi->sdf), GFP_ATOMIC);
                if (!pdi->sdf) {
					printk_ratelimited("%s:%d Failed to allocate SDF\n", __func__, __LINE__);
                    return -ENOMEM;
				}
            }
            sdf = pdi->sdf;

            if (sdf_attrs[GTP5G_SDF_FILTER_FLOW_DESCRIPTION] &&
                !nla_parse_nested(rule_attrs, 
									GTP5G_FLOW_DESCRIPTION_ATTR_MAX, 
									sdf_attrs[GTP5G_SDF_FILTER_FLOW_DESCRIPTION], 
									NULL, 
									NULL)) {
                if (!rule_attrs[GTP5G_FLOW_DESCRIPTION_ACTION] ||
                    !rule_attrs[GTP5G_FLOW_DESCRIPTION_DIRECTION] ||
                    !rule_attrs[GTP5G_FLOW_DESCRIPTION_PROTOCOL] ||
                    !rule_attrs[GTP5G_FLOW_DESCRIPTION_SRC_IPV4] ||
                    !rule_attrs[GTP5G_FLOW_DESCRIPTION_DEST_IPV4])
                    return -EINVAL;

                if (!sdf->rule) {
                    sdf->rule = kzalloc(sizeof(*sdf->rule), GFP_ATOMIC);
                    if (!sdf->rule) {
						printk_ratelimited("%s:%d Failed to allocate SDF's Rule\n", 
								__func__, __LINE__);
                        return -ENOMEM;
					}
                }
                rule = sdf->rule;

                rule->action = nla_get_u8(rule_attrs[GTP5G_FLOW_DESCRIPTION_ACTION]);
                rule->direction = nla_get_u8(rule_attrs[GTP5G_FLOW_DESCRIPTION_DIRECTION]);
                rule->proto = nla_get_u8(rule_attrs[GTP5G_FLOW_DESCRIPTION_PROTOCOL]);
                rule->src.s_addr = nla_get_be32(rule_attrs[GTP5G_FLOW_DESCRIPTION_SRC_IPV4]);
                rule->dest.s_addr = nla_get_be32(rule_attrs[GTP5G_FLOW_DESCRIPTION_DEST_IPV4]);

                if (rule_attrs[GTP5G_FLOW_DESCRIPTION_SRC_MASK])
                    rule->smask.s_addr = nla_get_be32(rule_attrs[GTP5G_FLOW_DESCRIPTION_SRC_MASK]);
                else
                    rule->smask.s_addr = -1;

                if (rule_attrs[GTP5G_FLOW_DESCRIPTION_DEST_MASK])
                    rule->dmask.s_addr = nla_get_be32(rule_attrs[GTP5G_FLOW_DESCRIPTION_DEST_MASK]);
                else
                    rule->dmask.s_addr = -1;

                if (rule_attrs[GTP5G_FLOW_DESCRIPTION_SRC_PORT]) {
                    u32 *sport_encode = nla_data(rule_attrs[GTP5G_FLOW_DESCRIPTION_SRC_PORT]);
                    rule->sport_num = nla_len(rule_attrs[GTP5G_FLOW_DESCRIPTION_SRC_PORT]) / sizeof(u32);
                    if (rule->sport)
                        kfree(rule->sport);
                    rule->sport = kzalloc(rule->sport_num * sizeof(*rule->sport), GFP_ATOMIC);
                    if (!rule->sport) {
						printk_ratelimited("%s:%d Failed to allocate SDF's Rule Source Port\n", 
								__func__, __LINE__);
                        return -ENOMEM;
					}

                    for (i = 0; i < rule->sport_num; i++) {
                        if ((sport_encode[i] & 0xFFFF) <= (sport_encode[i] >> 16)) {
                            rule->sport[i].start = (sport_encode[i] & 0xFFFF);
                            rule->sport[i].end = (sport_encode[i] >> 16);
                        } else {
                            rule->sport[i].start = (sport_encode[i] >> 16);
                            rule->sport[i].end = (sport_encode[i] & 0xFFFF);
                        }
                    }
                }

                if (rule_attrs[GTP5G_FLOW_DESCRIPTION_DEST_PORT]) {
                    u32 *dport_encode = nla_data(rule_attrs[GTP5G_FLOW_DESCRIPTION_DEST_PORT]);
                    rule->dport_num = nla_len(rule_attrs[GTP5G_FLOW_DESCRIPTION_DEST_PORT]) / sizeof(u32);

                    if (rule->dport)
                        kfree(rule->dport);

                    rule->dport = kzalloc(rule->dport_num * sizeof(*rule->dport), GFP_ATOMIC);
                    if (!rule->dport) {
						printk_ratelimited("%s:%d Failed to allocate SDF's Rule Destination Port\n", 
								__func__, __LINE__);
                        return -ENOMEM;
					}

                    for (i = 0; i < rule->dport_num; i++) {
                        if ((dport_encode[i] & 0xFFFF) <= (dport_encode[i] >> 16)) {
                            rule->dport[i].start = (dport_encode[i] & 0xFFFF);
                            rule->dport[i].end = (dport_encode[i] >> 16);
                        } else {
                            rule->dport[i].start = (dport_encode[i] >> 16);
                            rule->dport[i].end = (dport_encode[i] & 0xFFFF);
                        }
                    }
                }
            }

            if (sdf_attrs[GTP5G_SDF_FILTER_TOS_TRAFFIC_CLASS]) {
                if (!sdf->tos_traffic_class) {
                   	sdf->tos_traffic_class = kzalloc(sizeof(*sdf->tos_traffic_class), GFP_ATOMIC);
                    if (!sdf->tos_traffic_class) {
						printk_ratelimited("%s:%d Failed to allocate SDF's TOS Traffic class\n", 
								__func__, __LINE__);
                        return -ENOMEM;
					}
                }
                *sdf->tos_traffic_class = nla_get_u16(sdf_attrs[GTP5G_SDF_FILTER_TOS_TRAFFIC_CLASS]);
            }

            if (sdf_attrs[GTP5G_SDF_FILTER_SECURITY_PARAMETER_INDEX]) {
                if (!sdf->security_param_idx) {
					sdf->security_param_idx = kzalloc(sizeof(*sdf->security_param_idx), GFP_ATOMIC);
                    if (!sdf->security_param_idx) {
						printk_ratelimited("%s:%d Failed to allocate SDF's Security Param Index\n", 
								__func__, __LINE__);
                        return -ENOMEM;
					}
                }
                *sdf->security_param_idx = nla_get_u32(sdf_attrs[GTP5G_SDF_FILTER_SECURITY_PARAMETER_INDEX]);
            }

            if (sdf_attrs[GTP5G_SDF_FILTER_FLOW_LABEL]) {
                if (!sdf->flow_label) {
					sdf->flow_label = kzalloc(sizeof(*sdf->flow_label), GFP_ATOMIC);
                    if (!sdf->flow_label) {
						printk_ratelimited("%s:%d Failed to allocate SDF's Flow label\n", 
								__func__, __LINE__);
                        return -ENOMEM;
					}
                }
                *sdf->flow_label = nla_get_u32(sdf_attrs[GTP5G_SDF_FILTER_FLOW_LABEL]);
            }

            if (sdf_attrs[GTP5G_SDF_FILTER_SDF_FILTER_ID]) {
                if (!sdf->bi_id) {
                   	sdf->bi_id = kzalloc(sizeof(*sdf->bi_id), GFP_ATOMIC);
                    if (!sdf->bi_id) {
						printk_ratelimited("%s:%d Failed to allocate SDF's Filter id\n", 
								__func__, __LINE__);
                        return -ENOMEM;
					}
                }
                *sdf->bi_id = nla_get_u32(sdf_attrs[GTP5G_SDF_FILTER_SDF_FILTER_ID]);
            }
        }
    }

    if (!hlist_unhashed(&pdr->hlist_i_teid))
        hlist_del_rcu(&pdr->hlist_i_teid);

    if (!hlist_unhashed(&pdr->hlist_addr))
        hlist_del_rcu(&pdr->hlist_addr);

    // Update hlist table
    if ((pdi = pdr->pdi)) {
        if ((f_teid = pdi->f_teid)) {
            last_ppdr = NULL;
            head = &gtp->i_teid_hash[u32_hashfn(f_teid->teid) % gtp->hash_size];
            hlist_for_each_entry_rcu(ppdr, head, hlist_i_teid) {
                if (pdr->precedence > ppdr->precedence)
                    last_ppdr = ppdr;
                else
                    break;
            }

            if (!last_ppdr)
                hlist_add_head_rcu(&pdr->hlist_i_teid, head);
            else
                hlist_add_behind_rcu(&pdr->hlist_i_teid, &last_ppdr->hlist_i_teid);
        } else if (pdi->ue_addr_ipv4) {
            last_ppdr = NULL;
            head = &gtp->addr_hash[u32_hashfn(pdi->ue_addr_ipv4->s_addr) % gtp->hash_size];
            hlist_for_each_entry_rcu(ppdr, head, hlist_addr) {
                if (pdr->precedence > ppdr->precedence)
                    last_ppdr = ppdr;
                else
                    break;
            }

            if (!last_ppdr)
                hlist_add_head_rcu(&pdr->hlist_addr, head);
            else
                hlist_add_behind_rcu(&pdr->hlist_addr, &last_ppdr->hlist_addr);
        }
    }

    return 0;
}

static int gtp5g_dev_init(struct net_device *dev)
{
    struct gtp5g_dev *gtp = netdev_priv(dev);

    gtp->dev = dev;

    dev->tstats = netdev_alloc_pcpu_stats(struct pcpu_sw_netstats);
    if (!dev->tstats)
        return -ENOMEM;

    return 0;
}

static void __gtp5g_encap_destroy(struct sock *sk)
{
    struct gtp5g_dev *gtp;

    lock_sock(sk);
    gtp = sk->sk_user_data;
    if (gtp) {
        gtp->sk1u = NULL;
        udp_sk(sk)->encap_type = 0;
        rcu_assign_sk_user_data(sk, NULL);
        sock_put(sk);
    }
    release_sock(sk);
}

static void gtp5g_encap_disable_sock(struct sock *sk)
{
    if (!sk)
        return;

    __gtp5g_encap_destroy(sk);
}

static void gtp5g_encap_disable(struct gtp5g_dev *gtp)
{
    gtp5g_encap_disable_sock(gtp->sk1u);
}

static void gtp5g_dev_uninit(struct net_device *dev)
{
    struct gtp5g_dev *gtp = netdev_priv(dev);

    gtp5g_encap_disable(gtp);
    free_percpu(dev->tstats);
}

struct gtp5g_pktinfo {
    struct sock                   *sk;
    struct iphdr                  *iph;
    struct flowi4                 fl4;
    struct rtable                 *rt;
    struct outer_header_creation  *hdr_creation;
	struct gtp5g_qer			  *qer; 
    struct net_device             *dev;
    __be16                        gtph_port;
};

static void gtp5g_push_header(struct sk_buff *skb, struct gtp5g_pktinfo *pktinfo)
{
    int payload_len = skb->len;
    struct gtpv1_hdr *gtp1;
	gtpv1_hdr_opt_t	*gtp1opt;
	ext_pdu_sess_ctr_t *dl_pdu_sess;
    int ext_flag = 0;

    //printk_ratelimited("%s:%d Entry SKBLen(%u) GTP-U V1(%zu) Opt(%zu) DL_PDU(%zu)\n", 
	//		__func__, __LINE__, payload_len, sizeof(*gtp1), 
	//		sizeof(*gtp1opt), sizeof(*dl_pdu_sess));

    pktinfo->gtph_port = pktinfo->hdr_creation->port;

    /* Suppport for extension header, sequence number and N-PDU.
     * Update the length field if any of them is available.
     */
    if (pktinfo->qer) {
        ext_flag = 1; 

		/* Push PDU Session container information */
		dl_pdu_sess = skb_push(skb, sizeof(*dl_pdu_sess));
		/* Multiple of 4 (TODO include PPI) */
		dl_pdu_sess->length = 1; 
		dl_pdu_sess->pdu_sess_ctr.type_spare = 0; /* For DL */
		dl_pdu_sess->pdu_sess_ctr.u.dl.ppp_rqi_qfi = pktinfo->qer->qfi; 
		//TODO: PPI
		dl_pdu_sess->next_ehdr_type = 0; /* No more extension Header */
        
        /* Push optional header information */
		gtp1opt = skb_push(skb, sizeof(*gtp1opt));
		gtp1opt->seq_number = 0;
    	gtp1opt->NPDU = 0;
    	gtp1opt->next_ehdr_type = 0x85; /* PDU Session Container */
        // Increment the GTP-U payload length by size of optional headers length
        payload_len += (sizeof(*gtp1opt) + sizeof(*dl_pdu_sess));
	} 

    /* Bits 8  7  6  5  4  3  2	 1
     *	  +--+--+--+--+--+--+--+--+
     *	  |version |PT| 0| E| S|PN|
     *	  +--+--+--+--+--+--+--+--+
     *	    0  0  1  1	0  0  0  0
     */
    gtp1 = skb_push(skb, sizeof(*gtp1));
	gtp1->flags	= 0x30; /* v1, GTP-non-prime. */
    if (ext_flag) 
        gtp1->flags	|= GTPV1_HDR_FLG_EXTHDR; /* v1, Extension header enabled */ 
    gtp1->type	= GTP_TPDU;
    gtp1->tid = pktinfo->hdr_creation->teid;
    gtp1->length = htons(payload_len); 		/* Excluded the header length of gtpv1 */

    //printk_ratelimited("%s:%d QER Found GTP-U Flg(%u) GTPU-L(%u) SkbLen(%u)\n", 
	//		__func__, __LINE__, gtp1->flags, ntohs(gtp1->length), skb->len);
}

static inline void gtp5g_set_pktinfo_ipv4(struct gtp5g_pktinfo *pktinfo,
                                        struct sock *sk, struct iphdr *iph,
                                        struct outer_header_creation *hdr_creation,
										struct gtp5g_qer *qer,
                                        struct rtable *rt,
                                        struct flowi4 *fl4,
                                        struct net_device *dev)
{
	pktinfo->sk            = sk;
	pktinfo->iph           = iph;
	pktinfo->hdr_creation  = hdr_creation;
	pktinfo->qer  		   = qer;
	pktinfo->rt            = rt;
	pktinfo->fl4           = *fl4;
	pktinfo->dev           = dev;
}

static struct rtable *ip4_find_route(struct sk_buff *skb, struct iphdr *iph,
						struct sock *sk, struct net_device *gtp_dev, 
						__be32 saddr, __be32 daddr, struct flowi4 *fl4)
{
	struct rtable *rt;
	__be16 df;
	int mtu;

	memset(fl4, 0, sizeof(*fl4));
	fl4->flowi4_oif = sk->sk_bound_dev_if;
	fl4->daddr	   = daddr;
	fl4->saddr	   = (saddr ? saddr : inet_sk(sk)->inet_saddr);
	fl4->flowi4_tos		= RT_CONN_FLAGS(sk);
	fl4->flowi4_proto	= sk->sk_protocol;

	rt = ip_route_output_key(dev_net(gtp_dev), fl4);
	if (IS_ERR(rt)) {
		netdev_dbg(gtp_dev, "no route to %pI4\n", &iph->daddr);
		gtp_dev->stats.tx_carrier_errors++;
		goto err;
	}

	if (rt->dst.dev == gtp_dev) {
		netdev_dbg(gtp_dev, "circular route to %pI4\n", &iph->daddr);
		gtp_dev->stats.collisions++;
		goto err_rt;
	}

	skb_dst_drop(skb);

	/* This is similar to tnl_update_pmtu(). */
	df = iph->frag_off;
	if (df) {
		mtu = dst_mtu(&rt->dst) - gtp_dev->hard_header_len -
            sizeof(struct iphdr) - sizeof(struct udphdr);
        // GTPv1
        mtu -= sizeof(struct gtpv1_hdr);
	}
    else {
		mtu = dst_mtu(&rt->dst);
	}
	
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
	rt->dst.ops->update_pmtu(&rt->dst, NULL, skb, mtu, false);
#else
	rt->dst.ops->update_pmtu(&rt->dst, NULL, skb, mtu);
#endif
	if (!skb_is_gso(skb) && (iph->frag_off & htons(IP_DF)) &&
	    mtu < ntohs(iph->tot_len)) {
		netdev_dbg(gtp_dev, "packet too big, fragmentation needed\n");
		memset(IPCB(skb), 0, sizeof(*IPCB(skb)));
		icmp_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED,
			  htonl(mtu));
		goto err_rt;
	}

	return rt;
err_rt:
	ip_rt_put(rt);
err:
	return ERR_PTR(-ENOENT);
}

static int ip_xmit(struct sk_buff *skb, struct sock *sk, struct net_device *gtp_dev) 
{
    struct iphdr *iph = ip_hdr(skb);
	struct flowi4 fl4;
	struct rtable *rt;

	rt = ip4_find_route(skb, iph, sk, gtp_dev, 0, iph->daddr, &fl4);
	if (IS_ERR(rt))
		return -EBADMSG;

    skb_dst_set(skb, &rt->dst);
    
    if (ip_local_out(dev_net(gtp_dev), sk, skb) < 0) {
        pr_err("dev error\n");
        return -1;
    }
    return 0;
}

static int gtp5g_drop_skb_ipv4(struct sk_buff *skb, struct net_device *dev)
{
    dev->stats.tx_dropped++;
    dev_kfree_skb(skb);
    return 0;
}

static int gtp5g_fwd_skb_ipv4(struct sk_buff *skb, 
		struct net_device *dev,
		struct gtp5g_pktinfo *pktinfo, 
		struct gtp5g_pdr *pdr)
{
    struct rtable *rt;
    struct flowi4 fl4;
    struct iphdr *iph = ip_hdr(skb);
    struct outer_header_creation *hdr_creation;

    if (!(pdr->far && pdr->far->fwd_param && pdr->far->fwd_param->hdr_creation)) {
        netdev_dbg(dev, "Unknown RAN address\n");
        dev->stats.tx_carrier_errors++;
        goto err;
    }

    hdr_creation = pdr->far->fwd_param->hdr_creation;
    rt = ip4_find_route(skb, iph, pdr->sk, dev, 
                        pdr->role_addr_ipv4.s_addr, 
						hdr_creation->peer_addr_ipv4.s_addr, 
						&fl4);
	if (IS_ERR(rt))
        goto err;

	if (!pdr->qer) {
		gtp5g_set_pktinfo_ipv4(pktinfo, pdr->sk, iph, hdr_creation, NULL, rt, &fl4, dev);
	} else {
		gtp5g_set_pktinfo_ipv4(pktinfo, pdr->sk, iph, hdr_creation, pdr->qer, rt, &fl4, dev);
	}

    gtp5g_push_header(skb, pktinfo);

    return FAR_ACTION_FORW;

err:
    return -EBADMSG;
}

static int gtp5g_buf_skb_ipv4(struct sk_buff *skb, struct net_device *dev,
                                struct gtp5g_pdr *pdr)
{
    int rt = 0;
    // TODO: handle nonlinear part
    if (unix_sock_send(pdr, skb->data, skb_headlen(skb)) < 0)
        rt = -EBADMSG;

    return rt;
}

static int gtp5g_handle_skb_ipv4(struct sk_buff *skb, struct net_device *dev,
                                struct gtp5g_pktinfo *pktinfo)
{
    struct gtp5g_dev *gtp = netdev_priv(dev);
    struct gtp5g_pdr *pdr;
    struct gtp5g_far *far;
    struct gtp5g_qer *qer;
    struct iphdr *iph;

    /* Read the IP destination address and resolve the PDR.
     * Prepend PDR header with TEI/TID from PDR.
     */
    iph = ip_hdr(skb);
    if (gtp->role == GTP5G_ROLE_UPF)
        pdr = pdr_find_by_ipv4(gtp, skb, 0, iph->daddr);
    else
        pdr = pdr_find_by_ipv4(gtp, skb, 0, iph->saddr);

    if (!pdr) {
        netdev_dbg(dev, "no PDR found for %pI4, skip\n",
                   &iph->daddr);
        return -ENOENT;
    }
    netdev_dbg(dev, "found PDR %p\n", pdr);

	/* TODO: QoS rule have to apply before apply FAR 
	 * */
	qer = pdr->qer;
	if (qer) {
		netdev_dbg(dev, "%s:%d QER Rule found, id(%#x) qfi(%#x) TODO\n", 
				__func__, __LINE__, qer->id, qer->qfi);
	} 

    far = pdr->far;
    if (far) {
        // One and only one of the DROP, FORW and BUFF flags shall be set to 1.
        // The NOCP flag may only be set if the BUFF flag is set.
        // The DUPL flag may be set with any of the DROP, FORW, BUFF and NOCP flags.
        switch (far->action & FAR_ACTION_MASK) {
            case FAR_ACTION_DROP:
                return gtp5g_drop_skb_ipv4(skb, dev);
            case FAR_ACTION_FORW:
                return gtp5g_fwd_skb_ipv4(skb, dev, pktinfo, pdr);
            case FAR_ACTION_BUFF:
                return gtp5g_buf_skb_ipv4(skb, dev, pdr);
            default:
                pr_err("Unspec apply action[%u] in FAR[%u] and related to PDR[%u]",
                    far->action, far->id, pdr->id);
        }
    }

    return -ENOENT;
}

static void gtp5g_xmit_skb_ipv4(struct sk_buff *skb, struct gtp5g_pktinfo *pktinfo, u32 action)
{
    if (action & FAR_ACTION_FORW) {
        netdev_dbg(pktinfo->dev, "gtp -> IP src: %pI4 dst: %pI4\n",
                   &pktinfo->iph->saddr, &pktinfo->iph->daddr);
        udp_tunnel_xmit_skb(pktinfo->rt, pktinfo->sk, skb,
                            pktinfo->fl4.saddr, pktinfo->fl4.daddr,
                            pktinfo->iph->tos,
                            ip4_dst_hoplimit(&pktinfo->rt->dst),
                            0,
                            pktinfo->gtph_port, pktinfo->gtph_port,
                            true, true);
    }
}

/**
 * Entry function for Downlink packets
 * */
static netdev_tx_t gtp5g_dev_xmit(struct sk_buff *skb, struct net_device *dev)
{
    unsigned int proto = ntohs(skb->protocol);
    struct gtp5g_pktinfo pktinfo;
    int ret;

    /* Ensure there is sufficient headroom. */
    if (skb_cow_head(skb, dev->needed_headroom))
        goto tx_err;

    skb_reset_inner_headers(skb);

    /* PDR lookups in gtp5g_build_skb_*() need rcu read-side lock. */
    rcu_read_lock();
    switch (proto) {
    case ETH_P_IP:
        //printk_ratelimited("%s:%d Dowlink Packet received, skb.len(%u)\n", 
		//	__func__, __LINE__, skb->len);
        ret = gtp5g_handle_skb_ipv4(skb, dev, &pktinfo);
        //printk_ratelimited("%s:%d Dowlink Packet processed ret(%u) skb.len(%u)\n", 
		//	__func__, __LINE__, ret, skb->len);
        break;
    default:
        ret = -EOPNOTSUPP;
    }
    rcu_read_unlock();

    if (ret < 0)
        goto tx_err;

    switch (proto) {
    case ETH_P_IP:
        gtp5g_xmit_skb_ipv4(skb, &pktinfo, ret);
        break;
    }

    return NETDEV_TX_OK;

tx_err:
    dev->stats.tx_errors++;
    dev_kfree_skb(skb);
    return NETDEV_TX_OK;
}

static const struct net_device_ops gtp5g_netdev_ops = {
    .ndo_init           = gtp5g_dev_init,
    .ndo_uninit         = gtp5g_dev_uninit,
    .ndo_start_xmit     = gtp5g_dev_xmit,
    .ndo_get_stats64    = ip_tunnel_get_stats64,
};

static void pdr_context_free(struct rcu_head *head)
{
    struct gtp5g_pdr *pdr = container_of(head, struct gtp5g_pdr, rcu_head);
    struct gtp5g_pdi *pdi;
    struct sdf_filter *sdf;

    if (!pdr)
        return;

    sock_put(pdr->sk);

    if (pdr->outer_header_removal) kfree(pdr->outer_header_removal);

    pdi = pdr->pdi;
    if (pdi) {
        if (pdi->ue_addr_ipv4)
			kfree(pdi->ue_addr_ipv4);
        if (pdi->f_teid)
			kfree(pdi->f_teid);
        if (pdr->pdi)
			kfree(pdr->pdi);
        if (pdr->far_id)
			kfree(pdr->far_id);
		if (pdr->qer_id)
			kfree(pdr->qer_id);

        sdf = pdi->sdf;
        if (sdf) {
            if (sdf->rule) {
                if (sdf->rule->sport)
					kfree(sdf->rule->sport);
                if (sdf->rule->dport)
					kfree(sdf->rule->dport);
                if (sdf->rule)
					kfree(sdf->rule);
            }
            if (sdf->tos_traffic_class)
				kfree(sdf->tos_traffic_class);
            if (sdf->security_param_idx)
				kfree(sdf->security_param_idx);
            if (sdf->flow_label)
				kfree(sdf->flow_label);
            if (sdf->bi_id)
				kfree(sdf->bi_id);
        }
    }

    unix_sock_client_delete(pdr);
    kfree(pdr);
}

static void pdr_context_delete(struct gtp5g_pdr *pdr)
{
    if (!pdr)
        return;

    if (!hlist_unhashed(&pdr->hlist_id))
        hlist_del_rcu(&pdr->hlist_id);

    if (!hlist_unhashed(&pdr->hlist_i_teid))
        hlist_del_rcu(&pdr->hlist_i_teid);

    if (!hlist_unhashed(&pdr->hlist_addr))
        hlist_del_rcu(&pdr->hlist_addr);

    if (!hlist_unhashed(&pdr->hlist_related_far))
        hlist_del_rcu(&pdr->hlist_related_far);

    if (!hlist_unhashed(&pdr->hlist_related_qer))
        hlist_del_rcu(&pdr->hlist_related_qer);

    call_rcu(&pdr->rcu_head, pdr_context_free);
}

static void far_context_free(struct rcu_head *head)
{
    struct gtp5g_far *far = container_of(head, struct gtp5g_far, rcu_head);
    struct forwarding_parameter *fwd_param = far->fwd_param;

    if (!far)
        return;

    if (fwd_param) {
        if (fwd_param->hdr_creation) 
			kfree(fwd_param->hdr_creation);
        if (fwd_param->fwd_policy)
			kfree(fwd_param->fwd_policy);
    }

    if (fwd_param)
		kfree(fwd_param);

    kfree(far);
}

static void far_context_delete(struct gtp5g_far *far)
{
    struct gtp5g_dev *gtp = netdev_priv(far->dev);
    struct hlist_head *head;
    struct gtp5g_pdr *pdr;

    if (!far)
        return;

    if (!hlist_unhashed(&far->hlist_id))
        hlist_del_rcu(&far->hlist_id);

    head = &gtp->related_far_hash[u32_hashfn(far->id) % gtp->hash_size];
    hlist_for_each_entry_rcu(pdr, head, hlist_related_far) {
        if (*pdr->far_id == far->id) {
            pdr->far = NULL;
            unix_sock_client_delete(pdr);
        }
    }

    call_rcu(&far->rcu_head, far_context_free);
}

static int gtp5g_hashtable_new(struct gtp5g_dev *gtp, int hsize)
{
    int i;

    gtp->addr_hash = kmalloc_array(hsize, sizeof(struct hlist_head),
                       GFP_KERNEL);
    if (gtp->addr_hash == NULL)
        return -ENOMEM;

    gtp->i_teid_hash = kmalloc_array(hsize, sizeof(struct hlist_head),
                      GFP_KERNEL);
    if (gtp->i_teid_hash == NULL)
        goto err1;

    gtp->pdr_id_hash = kmalloc_array(hsize, sizeof(struct hlist_head),
                       GFP_KERNEL);
    if (gtp->pdr_id_hash == NULL)
        goto err2;

    gtp->far_id_hash = kmalloc_array(hsize, sizeof(struct hlist_head),
                       GFP_KERNEL);
	if (gtp->far_id_hash == NULL)
        goto err3;

	gtp->qer_id_hash = kmalloc_array(hsize, sizeof(struct hlist_head),
                       GFP_KERNEL);
    if (gtp->qer_id_hash == NULL)
        goto err4;

    gtp->related_far_hash = kmalloc_array(hsize, sizeof(struct hlist_head),
                        GFP_KERNEL);
    if (gtp->related_far_hash == NULL)
        goto err5;

    gtp->related_qer_hash = kmalloc_array(hsize, sizeof(struct hlist_head),
                        GFP_KERNEL);
    if (gtp->related_qer_hash == NULL)
        goto err6;


    gtp->hash_size = hsize;

    for (i = 0; i < hsize; i++) {
        INIT_HLIST_HEAD(&gtp->addr_hash[i]);
        INIT_HLIST_HEAD(&gtp->i_teid_hash[i]);
        INIT_HLIST_HEAD(&gtp->pdr_id_hash[i]);
        INIT_HLIST_HEAD(&gtp->far_id_hash[i]);
        INIT_HLIST_HEAD(&gtp->qer_id_hash[i]);
        INIT_HLIST_HEAD(&gtp->related_far_hash[i]);
        INIT_HLIST_HEAD(&gtp->related_qer_hash[i]);
    }

    return 0;

err6:
    kfree(gtp->related_far_hash);
err5:	
    kfree(gtp->qer_id_hash);
err4:
	kfree(gtp->far_id_hash);
err3:
    kfree(gtp->pdr_id_hash);
err2:
    kfree(gtp->i_teid_hash);
err1:
    kfree(gtp->addr_hash);
    return -ENOMEM;
}

static void gtp5g_hashtable_free(struct gtp5g_dev *gtp)
{
    struct gtp5g_pdr *pdr;
    struct gtp5g_far *far;
    struct gtp5g_qer *qer;
    int i;

    for (i = 0; i < gtp->hash_size; i++) {
        hlist_for_each_entry_rcu(pdr, &gtp->pdr_id_hash[i], hlist_id)
            pdr_context_delete(pdr);
        hlist_for_each_entry_rcu(far, &gtp->far_id_hash[i], hlist_id)
            far_context_delete(far);
        hlist_for_each_entry_rcu(qer, &gtp->qer_id_hash[i], hlist_id)
            qer_context_delete(qer);
    }

    synchronize_rcu();
    kfree(gtp->addr_hash);
    kfree(gtp->i_teid_hash);
    kfree(gtp->pdr_id_hash);
    kfree(gtp->far_id_hash);
    kfree(gtp->qer_id_hash);
    kfree(gtp->related_far_hash);
    kfree(gtp->related_qer_hash);
}

static void gtp5g_link_setup(struct net_device *dev)
{
    dev->netdev_ops = &gtp5g_netdev_ops;
    dev->needs_free_netdev = true;

    dev->hard_header_len = 0;
    dev->addr_len = 0;
    dev->mtu = ETH_DATA_LEN -
	    (sizeof(struct iphdr) +
	     sizeof(struct udphdr) +
	     sizeof(struct gtpv1_hdr));

    /* Zero header length. */
    dev->type = ARPHRD_NONE;
    dev->flags = IFF_POINTOPOINT | IFF_NOARP | IFF_MULTICAST;

    dev->priv_flags |= IFF_NO_QUEUE;
    dev->features |= NETIF_F_LLTX;
    netif_keep_dst(dev);

    /* TODO: Modify the headroom size based on
	 * what are the extension header going to supports.
	 * */
    dev->needed_headroom = LL_MAX_HEADER +
    			sizeof(struct iphdr) +
                  	sizeof(struct udphdr) +
                  	sizeof(struct gtpv1_hdr) + 
					sizeof(struct gtp1_hdr_opt) +
					sizeof(struct gtp1_hdr_ext_pdu_sess_ctr);
}

static int gtp5g_validate(struct nlattr *tb[], struct nlattr *data[],
            struct netlink_ext_ack *extack)
{
    if (!data)
        return -EINVAL;

    return 0;
}

static struct gtp5g_dev *gtp5g_find_dev(struct net *src_net, struct nlattr *nla[])
{
    struct gtp5g_dev *gtp = NULL;
    struct net_device *dev;
    struct net *net;

    /* Examine the link attributes and figure out which network namespace
     * we are talking about.
     */
    if (nla[GTP5G_NET_NS_FD])
        net = get_net_ns_by_fd(nla_get_u32(nla[GTP5G_NET_NS_FD]));
    else
        net = get_net(src_net);

    if (IS_ERR(net))
        return NULL;

    /* Check if there's an existing gtp5g device to configure */
    dev = dev_get_by_index_rcu(net, nla_get_u32(nla[GTP5G_LINK]));
    if (dev && dev->netdev_ops == &gtp5g_netdev_ops)
        gtp = netdev_priv(dev);

    put_net(net);

    return gtp;
}

static struct gtp5g_pdr *gtp5g_find_pdr_by_link(struct net *net, struct nlattr *nla[])
{
    struct gtp5g_dev *gtp;

    gtp = gtp5g_find_dev(net, nla);
    if (!gtp)
        return ERR_PTR(-ENODEV);

    if (nla[GTP5G_PDR_ID]) {
        u16 id = nla_get_u16(nla[GTP5G_PDR_ID]);
        return pdr_find_by_id(gtp, id);
    }

    return ERR_PTR(-EINVAL);
}

static struct gtp5g_pdr *gtp5g_find_pdr(struct net *net, struct nlattr *nla[])
{
    struct gtp5g_pdr *pdr;

    if (nla[GTP5G_LINK])
        pdr = gtp5g_find_pdr_by_link(net, nla);
    else
        pdr = ERR_PTR(-EINVAL);

    if (!pdr)
        pdr = ERR_PTR(-ENOENT);

    return pdr;
}

static struct gtp5g_far *gtp5g_find_far_by_link(struct net *net, struct nlattr *nla[])
{
    struct gtp5g_dev *gtp;

    gtp = gtp5g_find_dev(net, nla);
    if (!gtp)
        return ERR_PTR(-ENODEV);

    if (nla[GTP5G_FAR_ID]) {
        u32 id = nla_get_u32(nla[GTP5G_FAR_ID]);
        return far_find_by_id(gtp, id);
    }

    return ERR_PTR(-EINVAL);
}

static struct gtp5g_far *gtp5g_find_far(struct net *net, struct nlattr *nla[])
{
    struct gtp5g_far *far = NULL;

    if (nla[GTP5G_LINK])
        far = gtp5g_find_far_by_link(net, nla);
    else
        far = ERR_PTR(-EINVAL);

    if (!far)
        far = ERR_PTR(-ENOENT);

    return far;
}

static void gtp5g_encap_destroy(struct sock *sk)
{
    rtnl_lock();
    __gtp5g_encap_destroy(sk);
    rtnl_unlock();
}

static struct gtp5g_pdr *pdr_find_by_gtp1u(struct gtp5g_dev *gtp, struct sk_buff *skb,
                                  unsigned int hdrlen, u32 teid)
{
    struct iphdr *iph;
    __be32 *target_addr;
    struct hlist_head *head;
    struct gtp5g_pdr *pdr;
    struct gtp5g_pdi *pdi;

    switch(ntohs(skb->protocol)) {
    case ETH_P_IP:
        break;
    default:
        return NULL;
    }

    if (!pskb_may_pull(skb, hdrlen + sizeof(struct iphdr)))
        return NULL;

    iph = (struct iphdr *)(skb->data + hdrlen);
    target_addr = (gtp->role == GTP5G_ROLE_UPF ? &iph->saddr : &iph->daddr);

    head = &gtp->i_teid_hash[u32_hashfn(teid) % gtp->hash_size];
    hlist_for_each_entry_rcu(pdr, head, hlist_i_teid) {
        pdi = pdr->pdi;

        // GTP-U packet must check teid
        if (!(pdi->f_teid && pdi->f_teid->teid == teid))
            continue;

        if (pdi->ue_addr_ipv4)
            if (!(pdr->af == AF_INET && *target_addr == pdi->ue_addr_ipv4->s_addr))
                continue;

        if (pdi->sdf)
            if (!sdf_filter_match(pdi->sdf, skb, hdrlen, GTP5G_SDF_FILTER_OUT))
                continue;

        return pdr;
    }

    return NULL;
}

static int gtp5g_drop_skb_encap(struct sk_buff *skb, struct net_device *dev)
{
    dev->stats.tx_dropped++;
    dev_kfree_skb(skb);

    return 0;
}

static int gtp5g_fwd_skb_encap(struct sk_buff *skb, struct net_device *dev,
                                unsigned int hdrlen, struct gtp5g_pdr *pdr)
{
    struct gtp5g_far *far = pdr->far;
    struct forwarding_parameter *fwd_param = far->fwd_param;
    struct outer_header_creation *hdr_creation;
    struct forwarding_policy *fwd_policy;

    struct gtpv1_hdr *gtp1;
    struct iphdr *iph;
	struct udphdr *uh;

    struct pcpu_sw_netstats *stats;

    if (fwd_param) {
        if ((fwd_policy = fwd_param->fwd_policy))
            skb->mark = fwd_policy->mark;

        if ((hdr_creation = fwd_param->hdr_creation)) {
            // Just modify the teid and packet dest ip
            gtp1 = (struct gtpv1_hdr *)(skb->data + sizeof(struct udphdr));
            gtp1->tid = hdr_creation->teid;

            skb_push(skb, 20); // L3 Header Length
            iph = ip_hdr(skb);

            if (!pdr->pdi->f_teid) {
                pr_err("Unable to handle hdr removal + creation "
                    "due to pdr->pdi->f_teid not exist\n");
                return -1;
            }
            
            iph->saddr = pdr->pdi->f_teid->gtpu_addr_ipv4.s_addr;
            iph->daddr = hdr_creation->peer_addr_ipv4.s_addr;
            iph->check = 0;

            uh = udp_hdr(skb);
            uh->check = 0;

            if (ip_xmit(skb, pdr->sk, dev) < 0) {
                pr_err("ip_xmit error\n");
                return -1;
            }

            return 0;
        }
	}
	
    // Get rid of the GTP + UDP headers.
    if (iptunnel_pull_header(skb, hdrlen, skb->protocol,
                            !net_eq(sock_net(pdr->sk), dev_net(dev))))
        return -1;

    /* Now that the UDP and the GTP header have been removed, set up the
        * new network header. This is required by the upper layer to
        * calculate the transport header.
        */
    skb_reset_network_header(skb);

    skb->dev = dev;

    stats = this_cpu_ptr(skb->dev->tstats);
    u64_stats_update_begin(&stats->syncp);
    stats->rx_packets++;
    stats->rx_bytes += skb->len;
    u64_stats_update_end(&stats->syncp);

    netif_rx(skb);

    return 0;
}

static int gtp5g_buf_skb_encap(struct sk_buff *skb, struct net_device *dev, struct gtp5g_pdr *pdr)
{
    int rt = 0;
    if (unix_sock_send(pdr, skb->data, skb_headlen(skb)) < 0)
        rt = -EBADMSG;

    dev_kfree_skb(skb);

    return rt;
}

static int gtp5g_rx(struct gtp5g_pdr *pdr, struct sk_buff *skb,
                  unsigned int hdrlen, unsigned int role)
{
    int rt;
    struct gtp5g_far *far = pdr->far;
    //struct gtp5g_qer *qer = pdr->qer;

    if (!far) {
        pr_err("There is no FAR related to PDR(%u)", pdr->id);
        return -1;
    }

	//TODO: QER
	//if (qer) {
	//	printk_ratelimited("%s:%d QER Rule found, id(%#x) qfi(%#x)\n", __func__, __LINE__,
	//		qer->id, qer->qfi);
	//} 

    // TODO: not reading the value of outer_header_removal now,
    // just check if it is assigned.
    if (pdr->outer_header_removal) {
        // One and only one of the DROP, FORW and BUFF flags shall be set to 1.
        // The NOCP flag may only be set if the BUFF flag is set.
        // The DUPL flag may be set with any of the DROP, FORW, BUFF and NOCP flags.
        switch(far->action & FAR_ACTION_MASK) {
            case FAR_ACTION_DROP: 
                rt = gtp5g_drop_skb_encap(skb, pdr->dev);
                break;
            case FAR_ACTION_FORW:
                rt = gtp5g_fwd_skb_encap(skb, pdr->dev, hdrlen, pdr);
                break;
            case FAR_ACTION_BUFF:
                rt = gtp5g_buf_skb_encap(skb, pdr->dev, pdr);
                break;
            default:
                pr_err("Unspec apply action[%u] in FAR[%u] and related to PDR[%u]",
                    far->action, far->id, pdr->id);
                rt = -1;
        }
    } else {
        // TODO: this action is not supported
        pr_err("Unsupported action: not removing outer hdr of a non-gtp packet "
               "(which routed to the gtp interface and matches a PDR)");
        return -1;
    }
    
    return rt;
}
#if 0
static int get_gtpu_header_len(struct sk_buff *skb, u16 prefix_hdrlen)
{
    u8 *gtp1 = (skb->data + prefix_hdrlen);
	struct gtpv1_hdr *gtp1;
    u8 *ext_hdr = NULL;

    /** TS 29.281 Chapter 5.1 and Figure 5.1-1
     * GTP-U header at least 8 byte
     *
     * This field shall be present if and only if any one or more of the S, PN and E flags are set.
     * This field means seq number (2 Octect), N-PDU number (1 Octet) and  Next ext hdr type (1 Octet).
     */
    u16 rt_len = 8 + ((*gtp1 & 0x07) ? 4 : 0);

    /** TS 29.281 Chapter 5.2 and Figure 5.2.1-1
     * The length of the Extension header shall be defined in a variable length of 4 octets,
     * i.e. m+1 = n*4 octets, where n is a positive integer.
     */
    if (*gtp1 & 0x04) {
        /* ext_hdr will always point to "Next ext hdr type" */
        while (*(ext_hdr = gtp1 + rt_len - 1)) {
            rt_len += (*(++ext_hdr)) * 4;
            if (!pskb_may_pull(skb, rt_len + prefix_hdrlen))
                return -1;
        }
    }

    return rt_len;
}
#endif

static int get_gtpu_header_len(struct gtpv1_hdr *gtpv1, u16 prefix_hdrlen)
{
    u16 len = sizeof(*gtpv1);

    /** TS 29.281 Chapter 5.1 and Figure 5.1-1
     * GTP-U header at least 8 byte
     *
     * This field shall be present if and only if any one or more of the S, PN and E flags are set.
     * This field means seq number (2 Octect), N-PDU number (1 Octet) and  Next ext hdr type (1 Octet).
	 * 
     * TODO: Validate the Reserved flag set or not, if it is set then protocol error
     */
	if (gtpv1->flags & GTPV1_HDR_FLG_MASK) 
		len += 4;
	else
		return len;	 

    /** TS 29.281 Chapter 5.2 and Figure 5.2.1-1
     * The length of the Extension header shall be defined in a variable length of 4 octets,
     * i.e. m+1 = n*4 octets, where n is a positive integer.
     */
    if (gtpv1->flags & GTPV1_HDR_FLG_EXTHDR) {
		__u8 next_ehdr_type = 0;
		gtpv1_hdr_opt_t *gtpv1_opt = (gtpv1_hdr_opt_t *) ((u8 *) gtpv1 + sizeof(*gtpv1)); 	

		next_ehdr_type = gtpv1_opt->next_ehdr_type;
		while (next_ehdr_type) {
			switch (next_ehdr_type) {
			case GTPV1_NEXT_EXT_HDR_TYPE_85: 
			{
				ext_pdu_sess_ctr_t *etype85 = (ext_pdu_sess_ctr_t *) ((u8 *) gtpv1_opt + sizeof(*gtpv1_opt)); 
				pdu_sess_ctr_t *pdu_sess_info = &etype85->pdu_sess_ctr;

				//printk_ratelimited("%s: GTPV1_NEXT_EXT_HDR_TYPE_85\n", __func__);

				if (pdu_sess_info->type_spare == PDU_SESSION_INFO_TYPE0)
					return -1;
			
				//TODO: validate pdu_sess_ctr

				//Length should be multiple of 4
				len += (etype85->length * 4);
				next_ehdr_type = etype85->next_ehdr_type;
				break;
			}
				
			default:
				/* Unknown/Unhandled Extension Header Type */
				printk_ratelimited("%s: Invalid header type(%#x)\n", __func__, next_ehdr_type);
				return -1;
			}
		}
    }

    return len;
}

static int gtp1u_udp_encap_recv(struct gtp5g_dev *gtp, struct sk_buff *skb)
{
    unsigned int hdrlen = sizeof(struct udphdr) + sizeof(struct gtpv1_hdr);
    struct gtpv1_hdr *gtpv1;
    struct gtp5g_pdr *pdr;
    int gtpv1_hdr_len;

    if (!pskb_may_pull(skb, hdrlen))
        return -1;

    gtpv1 = (struct gtpv1_hdr *)(skb->data + sizeof(struct udphdr));
    if ((gtpv1->flags >> 5) != GTP_V1)
        return 1;

    if (gtpv1->type != GTP_TPDU)
        return 1;

    gtpv1_hdr_len = get_gtpu_header_len(gtpv1, sizeof(struct udphdr));
    if (gtpv1_hdr_len < 0) {
        netdev_dbg(gtp->dev, "Invalid extension header length or else\n");
        return -1;
	}

    hdrlen = sizeof(struct udphdr) + gtpv1_hdr_len;
    if (!pskb_may_pull(skb, hdrlen))
        return -1;

	//netdev_dbg(gtp->dev, "Total header len(%#x)\n", hdrlen);
    //gtp1 = (struct gtpv1_hdr *)(skb->data + sizeof(struct udphdr));
    pdr = pdr_find_by_gtp1u(gtp, skb, hdrlen, gtpv1->tid);
    if (!pdr) {
        netdev_dbg(gtp->dev, "No PDR match this skb : teid[%d]\n", ntohl(gtpv1->tid));
        return 1;
    }

    return gtp5g_rx(pdr, skb, hdrlen, gtp->role);
}

/**
 * Entry function for Uplink packets
 *
 * UDP encapsulation receive handler. See net/ipv4/udp.c.
 * Return codes: 0: success, <0: error, >0: pass up to userspace UDP socket.
 */
static int gtp5g_encap_recv(struct sock *sk, struct sk_buff *skb)
{
    struct gtp5g_dev *gtp;
    int ret = 0;

    gtp = rcu_dereference_sk_user_data(sk);
    if (!gtp)
        return 1;

    switch (udp_sk(sk)->encap_type) {
    case UDP_ENCAP_GTP1U:
        //netdev_dbg(gtp->dev, "Receive GTP-U v1 packet\n");
        ret = gtp1u_udp_encap_recv(gtp, skb);
        break;
    default:
        ret = -1; // Should not happen
    }

    switch(ret) {
    case 1:
        netdev_dbg(gtp->dev, "Pass up to the process\n");
        break;
    case 0:
        break;
    case -1:
        netdev_dbg(gtp->dev, "GTP packet has been dropped\n");
        kfree_skb(skb);
        ret = 0;
        break;
    }

    return ret;
}

static struct sock *gtp5g_encap_enable_socket(int fd, int type, struct gtp5g_dev *gtp)
{
    struct udp_tunnel_sock_cfg tuncfg = {NULL};
    struct socket *sock;
    struct sock *sk;
    int err;

    pr_debug("enable gtp5g on %d, %d\n", fd, type);

    sock = sockfd_lookup(fd, &err);
    if (!sock) {
        pr_debug("gtp5g socket fd[%d] not found\n", fd);
        return NULL;
    }

    if (sock->sk->sk_protocol != IPPROTO_UDP) {
        pr_debug("socket fd[%d] not UDP\n", fd);
        sk = ERR_PTR(-EINVAL);
        goto out_sock;
    }

    lock_sock(sock->sk);
    if (sock->sk->sk_user_data) {
        sk = ERR_PTR(-EBUSY);
        goto out_sock;
    }

    sk = sock->sk;
    sock_hold(sk);

    tuncfg.sk_user_data = gtp;
    tuncfg.encap_type = type;
    tuncfg.encap_rcv = gtp5g_encap_recv;
    tuncfg.encap_destroy = gtp5g_encap_destroy;

    setup_udp_tunnel_sock(sock_net(sock->sk), sock, &tuncfg);

out_sock:
    release_sock(sock->sk);
    sockfd_put(sock);
    return sk;
}

static int gtp5g_encap_enable(struct gtp5g_dev *gtp, struct nlattr *data[]) {
    struct sock *sk = NULL;
    unsigned int role = GTP5G_ROLE_UPF;

    if (data[IFLA_GTP5G_FD1]) {
        u32 fd1 = nla_get_u32(data[IFLA_GTP5G_FD1]);

        sk = gtp5g_encap_enable_socket(fd1, UDP_ENCAP_GTP1U, gtp);
        if (IS_ERR(sk))
            return PTR_ERR(sk);
    }

    if (data[IFLA_GTP5G_ROLE]) {
        role = nla_get_u32(data[IFLA_GTP5G_ROLE]);
        if (role > GTP5G_ROLE_RAN) {
            if (sk)
                gtp5g_encap_disable_sock(sk);
            return -EINVAL;
        }
    }

    gtp->sk1u = sk;
    gtp->role = role;

    return 0;
}

static int gtp5g_newlink(struct net *src_net, struct net_device *dev,
               struct nlattr *tb[], struct nlattr *data[],
               struct netlink_ext_ack *extack)
{
    struct gtp5g_dev *gtp;
    struct gtp5g_net *gn;
    int hashsize, err;

    if (!data[IFLA_GTP5G_FD1])
        return -EINVAL;

    gtp = netdev_priv(dev);

    err = gtp5g_encap_enable(gtp, data);
    if (err < 0)
        return err;

    if (!data[IFLA_GTP5G_PDR_HASHSIZE])
        hashsize = 1024;
    else
        hashsize = nla_get_u32(data[IFLA_GTP5G_PDR_HASHSIZE]);

    err = gtp5g_hashtable_new(gtp, hashsize);
    if (err < 0)
        goto out_encap;

    err = register_netdevice(dev);
    if (err < 0) {
        netdev_dbg(dev, "failed to register new netdev %d\n", err);
        goto out_hashtable;
    }

    gn = net_generic(dev_net(dev), gtp5g_net_id);
    list_add_rcu(&gtp->list, &gn->gtp5g_dev_list);

    netdev_dbg(dev, "registered new 5G GTP interface\n");

    return 0;

out_hashtable:
    gtp5g_hashtable_free(gtp);
out_encap:
    gtp5g_encap_disable(gtp);
    return err;

}

static void gtp5g_dellink(struct net_device *dev, struct list_head *head)
{
    struct gtp5g_dev *gtp = netdev_priv(dev);

    gtp5g_hashtable_free(gtp);
    list_del_rcu(&gtp->list);
    unregister_netdevice_queue(dev, head);

    netdev_dbg(dev, "deregistered 5G GTP interface\n");
}

static size_t gtp5g_get_size(const struct net_device *dev)
{
    return nla_total_size(sizeof(__u32));    /* IFLA_GTP5G_PDR_HASHSIZE */
}

static int gtp5g_fill_info(struct sk_buff *skb, const struct net_device *dev)
{
    struct gtp5g_dev *gtp = netdev_priv(dev);

    if (nla_put_u32(skb, IFLA_GTP5G_PDR_HASHSIZE, gtp->hash_size))
        goto nla_put_failure;

    return 0;

nla_put_failure:
    return -EMSGSIZE;
}

static const struct nla_policy gtp5g_policy[IFLA_GTP5G_MAX + 1] = {
    [IFLA_GTP5G_FD1]             = { .type = NLA_U32 },
    [IFLA_GTP5G_PDR_HASHSIZE]    = { .type = NLA_U32 },
    [IFLA_GTP5G_ROLE]            = { .type = NLA_U32 },
};

static struct rtnl_link_ops gtp5g_link_ops __read_mostly = {
    .kind         = "gtp5g",
    .maxtype      = IFLA_GTP5G_MAX,
    .policy       = gtp5g_policy,
    .priv_size    = sizeof(struct gtp5g_dev),
    .setup        = gtp5g_link_setup,
    .validate     = gtp5g_validate,
    .newlink      = gtp5g_newlink,
    .dellink      = gtp5g_dellink,
    .get_size     = gtp5g_get_size,
    .fill_info    = gtp5g_fill_info,
};

static struct genl_family gtp5g_genl_family;

static int gtp5g_gnl_add_pdr(struct gtp5g_dev *gtp, struct genl_info *info)
{
    struct net_device *dev = gtp->dev;
    struct gtp5g_pdr *pdr;
    int err = 0;
    u32 pdr_id;

    pdr_id = nla_get_u16(info->attrs[GTP5G_PDR_ID]);
    pdr = pdr_find_by_id(gtp, pdr_id);
    if (pdr) {
        if (info->nlhdr->nlmsg_flags & NLM_F_EXCL)
            return -EEXIST;
        else if (!(info->nlhdr->nlmsg_flags & NLM_F_REPLACE))
            return -EOPNOTSUPP;

        err = pdr_fill(pdr, gtp, info);
        if (err < 0) {
            netdev_dbg(dev, "5G GTP update PDR id(%u) fail\n", pdr_id);
            pdr_context_delete(pdr);
        } else {
            netdev_dbg(dev, "5G GTP update PDR id(%u)\n", pdr_id);
        }
        return err;
    }

    if (info->nlhdr->nlmsg_flags & NLM_F_REPLACE) {
		netdev_dbg(dev, "Failed nlmsg set to NLM_F_REPLACE\n");
        return -ENOENT;
	}

    if (info->nlhdr->nlmsg_flags & NLM_F_APPEND) {
		netdev_dbg(dev, "Failed nlmsg set to NLM_F_APPEND\n");
        return -EOPNOTSUPP;
	}

    // Check only at the creation part
    if (!info->attrs[GTP5G_PDR_PRECEDENCE]) {
		netdev_dbg(dev, "PDR precedence is not present\n");
        return -EINVAL;
	}

    pdr = kzalloc(sizeof(*pdr), GFP_ATOMIC);
    if (!pdr) {
		printk_ratelimited("%s:%d Failed to allocate PDR memory\n", __func__,
				__LINE__);
        return -ENOMEM;
	}

    sock_hold(gtp->sk1u);
    pdr->sk = gtp->sk1u;
    pdr->dev = gtp->dev;

    err = pdr_fill(pdr, gtp, info);
    if (err < 0) {
        pr_warn("5G GTP add PDR id(%u) fail: %d\n", pdr_id, err);
        pdr_context_delete(pdr);
    } else {
        hlist_add_head_rcu(&pdr->hlist_id, 
							&gtp->pdr_id_hash[u32_hashfn(pdr_id) % gtp->hash_size]);
        netdev_dbg(dev, "5G GTP add PDR id[%d]\n", pdr_id);
    }

    return err;
}

static int gtp5g_genl_add_pdr(struct sk_buff *skb, struct genl_info *info)
{
    struct gtp5g_dev *gtp;
    int err = 0;

    if (!info->attrs[GTP5G_PDR_ID] ||
        !info->attrs[GTP5G_LINK]) {
		printk_ratelimited("%s:%d PDR_ID or LINK value is not exists\n", __func__,
				__LINE__);
        return -EINVAL;
	}

    rtnl_lock();
    rcu_read_lock();

    gtp = gtp5g_find_dev(sock_net(skb->sk), info->attrs);
    if (!gtp) {
		printk_ratelimited("%s:%d Can't find the gtp5g_dev\n", __func__,__LINE__);
        err = -ENODEV;
        goto unlock;
    }

    err = gtp5g_gnl_add_pdr(gtp, info);

unlock:
    rcu_read_unlock();
    rtnl_unlock();
    return err;
}

static int gtp5g_genl_del_pdr(struct sk_buff *skb, struct genl_info *info)
{
    u16 id;
    struct gtp5g_pdr *pdr;
    int err = 0;

    if (!info->attrs[GTP5G_PDR_ID] ||
        !info->attrs[GTP5G_LINK]) {
		printk_ratelimited("%s:%d PDR_ID or LINK is not present\n",
				__func__, __LINE__);
        return -EINVAL;
	}

    id = nla_get_u16(info->attrs[GTP5G_PDR_ID]);

    rcu_read_lock();

    pdr = gtp5g_find_pdr(sock_net(skb->sk), info->attrs);
    if (IS_ERR(pdr)) {
        err = PTR_ERR(pdr);
        goto unlock;
    }

    netdev_dbg(pdr->dev, "5G GTP-U : delete PDR id[%d]\n", id);
    pdr_context_delete(pdr);

unlock:
    rcu_read_unlock();
    return err;
}

static int gtp5g_genl_fill_pdr(struct sk_buff *skb, u32 snd_portid, u32 snd_seq,
                               u32 type, struct gtp5g_pdr *pdr)
{
    void *genlh;
    struct nlattr *nest_pdi, *nest_f_teid, *nest_sdf, *nest_rule;
    struct gtp5g_pdi *pdi;
    struct local_f_teid *f_teid;
    struct sdf_filter *sdf;
    struct ip_filter_rule *rule;

    int i;
    u32 *u32_buf = kzalloc(0xff * sizeof(u32), GFP_KERNEL);
	if (!u32_buf) {
		printk_ratelimited("%s:%d Failed to allocate memory\n", __func__, __LINE__);
		goto out;
	}

    genlh = genlmsg_put(skb, snd_portid, snd_seq, &gtp5g_genl_family, 0, type);
    if (!genlh) 
        goto genlmsg_fail;

    if (nla_put_u16(skb, GTP5G_PDR_ID, pdr->id) ||
        nla_put_u32(skb, GTP5G_PDR_PRECEDENCE, pdr->precedence))
        goto genlmsg_fail;

    if (pdr->outer_header_removal) {
        if (nla_put_u8(skb, GTP5G_OUTER_HEADER_REMOVAL, *pdr->outer_header_removal))
            goto genlmsg_fail;
    }

    if (pdr->far_id) {
        if (nla_put_u32(skb, GTP5G_PDR_FAR_ID, *pdr->far_id))
            goto genlmsg_fail;
    }

    if (pdr->qer_id) {
        if (nla_put_u32(skb, GTP5G_PDR_QER_ID, *pdr->qer_id))
            goto genlmsg_fail;
    }

    if (pdr->role_addr_ipv4.s_addr) {
        if (nla_put_u32(skb, GTP5G_PDR_ROLE_ADDR_IPV4, pdr->role_addr_ipv4.s_addr))
            goto genlmsg_fail;
    }

    if (pdr->pdi) {
        if (!(nest_pdi = nla_nest_start(skb, GTP5G_PDR_PDI)))
            goto genlmsg_fail;

        pdi = pdr->pdi;
        if (pdi->ue_addr_ipv4) {
            if (nla_put_be32(skb, GTP5G_PDI_UE_ADDR_IPV4, pdi->ue_addr_ipv4->s_addr))
                goto genlmsg_fail;
        }

        if (pdi->f_teid) {
            if (!(nest_f_teid = nla_nest_start(skb, GTP5G_PDI_F_TEID)))
                goto genlmsg_fail;

            f_teid = pdi->f_teid;
            if (nla_put_u32(skb, GTP5G_F_TEID_I_TEID, ntohl(f_teid->teid)) ||
                nla_put_be32(skb, GTP5G_F_TEID_GTPU_ADDR_IPV4, f_teid->gtpu_addr_ipv4.s_addr))
                goto genlmsg_fail;

            nla_nest_end(skb, nest_f_teid);
        }

        if (pdi->sdf) {
            if (!(nest_sdf = nla_nest_start(skb, GTP5G_PDI_SDF_FILTER)))
                goto genlmsg_fail;

            sdf = pdi->sdf;
            if (sdf->rule) {
                if (!(nest_rule = nla_nest_start(skb, GTP5G_SDF_FILTER_FLOW_DESCRIPTION)))
                    goto genlmsg_fail;
                rule = sdf->rule;

                if (nla_put_u8(skb, GTP5G_FLOW_DESCRIPTION_ACTION, rule->action) ||
                    nla_put_u8(skb, GTP5G_FLOW_DESCRIPTION_DIRECTION, rule->direction) ||
                    nla_put_u8(skb, GTP5G_FLOW_DESCRIPTION_PROTOCOL, rule->proto) ||
                    nla_put_be32(skb, GTP5G_FLOW_DESCRIPTION_SRC_IPV4, rule->src.s_addr) ||
                    nla_put_be32(skb, GTP5G_FLOW_DESCRIPTION_DEST_IPV4, rule->dest.s_addr))
                    goto genlmsg_fail;

                if (rule->smask.s_addr != -1)
                    if (nla_put_be32(skb, GTP5G_FLOW_DESCRIPTION_SRC_MASK, rule->smask.s_addr))
                        goto genlmsg_fail;

                if (rule->dmask.s_addr != -1)
                    if (nla_put_be32(skb, GTP5G_FLOW_DESCRIPTION_DEST_MASK, rule->dmask.s_addr))
                        goto genlmsg_fail;

                if (rule->sport_num && rule->sport) {
                    for (i = 0; i < rule->sport_num; i++)
                        u32_buf[i] = rule->sport[i].start + (rule->sport[i].end << 16);
                    if (nla_put(skb, GTP5G_FLOW_DESCRIPTION_SRC_PORT,
                        rule->sport_num * sizeof(u32) / sizeof(char), u32_buf))
                        goto genlmsg_fail;
                }

                if (rule->dport_num && rule->dport) {
                    for (i = 0; i < rule->dport_num; i++)
                        u32_buf[i] = rule->dport[i].start + (rule->dport[i].end << 16);
                    if (nla_put(skb, GTP5G_FLOW_DESCRIPTION_DEST_PORT,
                        rule->dport_num * sizeof(u32) / sizeof(char), u32_buf))
                        goto genlmsg_fail;
                }

                nla_nest_end(skb, nest_rule);
            }

            if (sdf->tos_traffic_class)
                if (nla_put_u16(skb, GTP5G_SDF_FILTER_TOS_TRAFFIC_CLASS, *sdf->tos_traffic_class))
                    goto genlmsg_fail;

            if (sdf->security_param_idx)
                if (nla_put_u32(skb, GTP5G_SDF_FILTER_SECURITY_PARAMETER_INDEX, *sdf->security_param_idx))
                    goto genlmsg_fail;

            if (sdf->flow_label)
                if (nla_put_u32(skb, GTP5G_SDF_FILTER_FLOW_LABEL, *sdf->flow_label))
                    goto genlmsg_fail;

            if (sdf->bi_id)
                if (nla_put_u32(skb, GTP5G_SDF_FILTER_SDF_FILTER_ID, *sdf->bi_id))
                    goto genlmsg_fail;

            nla_nest_end(skb, nest_sdf);
        }

        nla_nest_end(skb, nest_pdi);
    }

    kfree(u32_buf);
    genlmsg_end(skb, genlh);

    return 0;

genlmsg_fail:
    kfree(u32_buf);
    genlmsg_cancel(skb, genlh);
out:
    return -EMSGSIZE;
}

static int gtp5g_genl_get_pdr(struct sk_buff *skb, struct genl_info *info)
{
    struct gtp5g_pdr *pdr;
    struct sk_buff *skb_ack;
    int err;

    if (!info->attrs[GTP5G_PDR_ID]) {
		printk_ratelimited("%s:%d PDR ID is not present\n", __func__, 
				__LINE__);
        return -EINVAL;
	}

    rcu_read_lock();

    pdr = gtp5g_find_pdr(sock_net(skb->sk), info->attrs);
    if (IS_ERR(pdr)) {
		printk_ratelimited("%s:%d PDR is not present\n", __func__, 
				__LINE__);
        err = PTR_ERR(pdr);
        goto unlock;
    }

    skb_ack = genlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);
    if (!skb_ack) {
		printk_ratelimited("%s:%d Failed to allocate skb ack\n", __func__, 
				__LINE__);
        err = -ENOMEM;
        goto unlock;
    }

    err = gtp5g_genl_fill_pdr(skb_ack, 
								NETLINK_CB(skb).portid,
                              	info->snd_seq, 
								info->nlhdr->nlmsg_type, 
								pdr);
    if (err < 0) {
		printk_ratelimited("%s:%d Failed to fill PDR err(%d)\n", __func__, 
				__LINE__, err);
        goto freebuf;
	}

    rcu_read_unlock();

    return genlmsg_unicast(genl_info_net(info), skb_ack, info->snd_portid);

freebuf:
    kfree_skb(skb_ack);
unlock:
    rcu_read_unlock();

    return err;
}

static int gtp5g_genl_dump_pdr(struct sk_buff *skb, struct netlink_callback *cb)
{
    /* netlink_callback->args
     * args[0] : index of gtp5g dev id
     * args[1] : index of gtp5g hash entry id in dev
     * args[2] : index of gtp5g pdr id
     * args[5] : set non-zero means it is finished
     */
    struct gtp5g_dev *gtp, *last_gtp = (struct gtp5g_dev *)cb->args[0];
    struct net *net = sock_net(skb->sk);
    struct gtp5g_net *gn = net_generic(net, gtp5g_net_id);
    int i, last_hash_entry_id = cb->args[1], ret;
    u16 pdr_id = cb->args[2];
    struct gtp5g_pdr *pdr;

    if (cb->args[5]) {
		printk_ratelimited("%s:%d Failed to dump callback args[5] is present\n",
				__func__, __LINE__);
        return 0;
	}

    list_for_each_entry_rcu(gtp, &gn->gtp5g_dev_list, list) {
        if (last_gtp && last_gtp != gtp)
            continue;
        else
            last_gtp = NULL;

        for (i = last_hash_entry_id; i < gtp->hash_size; i++) {
            hlist_for_each_entry_rcu(pdr, &gtp->pdr_id_hash[i], hlist_id) {
                if (pdr_id && pdr_id != pdr->id)
                    continue;
                else
                    pdr_id = 0;

                ret = gtp5g_genl_fill_pdr(skb, 
									NETLINK_CB(cb->skb).portid,
                                    cb->nlh->nlmsg_seq, 
									cb->nlh->nlmsg_type, 
									pdr);
                if (ret < 0) {
                    cb->args[0] = (unsigned long) gtp;
                    cb->args[1] = i;
                    cb->args[2] = pdr->id;
                    goto out;
                }
            }
        }
    }
    cb->args[5] = 1;

out:
    return skb->len;
}

static int gtp5g_gnl_add_far(struct gtp5g_dev *gtp, struct genl_info *info)
{
    struct net_device *dev = gtp->dev;
    struct gtp5g_far *far;
    int err = 0;
    u32 far_id;

    far_id = nla_get_u32(info->attrs[GTP5G_FAR_ID]);
    far = far_find_by_id(gtp, far_id);
    if (far) {
    	if (info->nlhdr->nlmsg_flags & NLM_F_EXCL)
            return -EEXIST;
        else if (!(info->nlhdr->nlmsg_flags & NLM_F_REPLACE))
            return -EOPNOTSUPP;

        err = far_fill(far, gtp, info);

        if (err < 0) {
            far_context_delete(far);
            pr_warn("5G GTP update FAR id[%d] fail: %d\n", far_id, err);
        } else {
            netdev_dbg(dev, "5G GTP update FAR id[%d]", far_id);
        }
        return err;
    }

    if (info->nlhdr->nlmsg_flags & NLM_F_REPLACE)
        return -ENOENT;

    if (info->nlhdr->nlmsg_flags & NLM_F_APPEND)
        return -EOPNOTSUPP;

    // Check only at the creation part
    if (!info->attrs[GTP5G_FAR_APPLY_ACTION])
        return -EINVAL;

    far = kzalloc(sizeof(*far), GFP_ATOMIC);
    if (!far) {
		printk_ratelimited("%s:%d Failed to allocate FAR\n", __func__, __LINE__);
        return -ENOMEM;
    }

    far->dev = gtp->dev;

    err = far_fill(far, gtp, info);
    if (err < 0) {
        netdev_dbg(dev, "5G GTP add FAR id[%d] fail", far_id);
        far_context_delete(far);
    } else {
        hlist_add_head_rcu(&far->hlist_id, 
			&gtp->far_id_hash[u32_hashfn(far_id) % gtp->hash_size]);
        netdev_dbg(dev, "5G GTP add FAR id[%d]", far_id);
    }

    return err;
}

static int gtp5g_genl_add_far(struct sk_buff *skb, struct genl_info *info)
{
    struct gtp5g_dev *gtp;
    int err = 0;

    if (!info->attrs[GTP5G_FAR_ID] ||
        !info->attrs[GTP5G_LINK]) {
		printk_ratelimited("%s:%d Failed to find FAR_ID or LINK in netlink\n", __func__,
				__LINE__);
        return -EINVAL;
	}

    rtnl_lock();
    rcu_read_lock();

    gtp = gtp5g_find_dev(sock_net(skb->sk), info->attrs);
    if (!gtp) {
		printk_ratelimited("%s:%d Failed to find the gtp5g_dev\n", __func__,
				__LINE__);
        err = -ENODEV;
        goto unlock;
    }

    err = gtp5g_gnl_add_far(gtp, info);

unlock:
    rcu_read_unlock();
    rtnl_unlock();
    return err;
}

static int gtp5g_genl_del_far(struct sk_buff *skb, struct genl_info *info)
{
    u32 id;
    struct gtp5g_far *far;
    int err = 0;

    if (!info->attrs[GTP5G_FAR_ID] ||
        !info->attrs[GTP5G_LINK]) {
		printk_ratelimited("%s:%d Failed to find FAR_ID or LINK in netlink\n",
				__func__, __LINE__);
        return -EINVAL;
	}

    id = nla_get_u32(info->attrs[GTP5G_FAR_ID]);

    rcu_read_lock();

    far = gtp5g_find_far(sock_net(skb->sk), info->attrs);
    if (IS_ERR(far)) {
		printk_ratelimited("%s:%d Failed to find far\n",
				__func__, __LINE__);
        err = PTR_ERR(far);
        goto unlock;
    }

    netdev_dbg(far->dev, "5G GTP-U : delete FAR id(%u)\n", id);
    far_context_delete(far);

unlock:
    rcu_read_unlock();
    return err;
}

static int gtp5g_genl_fill_far(struct sk_buff *skb, u32 snd_portid, u32 snd_seq,
                               u32 type, struct gtp5g_far *far)
{
    void *genlh;
    struct nlattr *nest_fwd_param, *nest_hdr_creation;
    struct forwarding_parameter *fwd_param;
    struct outer_header_creation *hdr_creation;
    struct forwarding_policy *fwd_policy;

    int cnt;
    struct gtp5g_dev *gtp = netdev_priv(far->dev);
    struct hlist_head *head;
    struct gtp5g_pdr *pdr;
    u16 *u16_buf = kzalloc(0xff * sizeof(u16), GFP_KERNEL);
	if (!u16_buf) {
		printk_ratelimited("%s:%d Failed to allocate buf\n", __func__, __LINE__);
		goto out;
	}

    genlh = genlmsg_put(skb, snd_portid, snd_seq, &gtp5g_genl_family, 0, type);
    if (!genlh)
        goto genlmsg_fail;

    if (nla_put_u32(skb, GTP5G_FAR_ID, far->id) ||
        nla_put_u8(skb, GTP5G_FAR_APPLY_ACTION, far->action))
        goto genlmsg_fail;

    if (far->fwd_param) {
        if (!(nest_fwd_param = nla_nest_start(skb, GTP5G_FAR_FORWARDING_PARAMETER)))
            goto genlmsg_fail;

        fwd_param = far->fwd_param;
        if (fwd_param->hdr_creation) {
            if (!(nest_hdr_creation = nla_nest_start(skb, GTP5G_FORWARDING_PARAMETER_OUTER_HEADER_CREATION)))
                goto genlmsg_fail;

            hdr_creation = fwd_param->hdr_creation;
            if (nla_put_u16(skb, GTP5G_OUTER_HEADER_CREATION_DESCRIPTION, hdr_creation->description) ||
                nla_put_u32(skb, GTP5G_OUTER_HEADER_CREATION_O_TEID, ntohl(hdr_creation->teid)) ||
                nla_put_be32(skb, GTP5G_OUTER_HEADER_CREATION_PEER_ADDR_IPV4, hdr_creation->peer_addr_ipv4.s_addr) ||
                nla_put_u16(skb, GTP5G_OUTER_HEADER_CREATION_PORT, ntohs(hdr_creation->port)))
                goto genlmsg_fail;

            nla_nest_end(skb, nest_hdr_creation);
        }

        if ((fwd_policy = fwd_param->fwd_policy))
            if (nla_put(skb, GTP5G_FORWARDING_PARAMETER_FORWARDING_POLICY, fwd_policy->len, fwd_policy->identifier))
                goto genlmsg_fail;

        nla_nest_end(skb, nest_fwd_param);
    }

    cnt = 0;    
    head = &gtp->related_far_hash[u32_hashfn(far->id) % gtp->hash_size];
    hlist_for_each_entry_rcu(pdr, head, hlist_related_far) {
        if (cnt >= 0xff)
            goto genlmsg_fail;

        if (*pdr->far_id == far->id)
            u16_buf[cnt++] = pdr->id;
    }

    if (cnt) {
        if (nla_put(skb, GTP5G_FAR_RELATED_TO_PDR, cnt * sizeof(u16) / sizeof(char), u16_buf))
            goto genlmsg_fail;
    }

    kfree(u16_buf);
    genlmsg_end(skb, genlh);
    return 0;

genlmsg_fail:
    kfree(u16_buf);
    genlmsg_cancel(skb, genlh);
out:
    return -EMSGSIZE;
}

static int gtp5g_genl_get_far(struct sk_buff *skb, struct genl_info *info)
{
    struct gtp5g_far *far;
    struct sk_buff *skb_ack;
    int err;

    if (!info->attrs[GTP5G_FAR_ID]) {
		printk_ratelimited("%s:%d Failed to find FAR_ID in netlink msg\n",
				__func__, __LINE__);
        return -EINVAL;
	}

    rcu_read_lock();

    far = gtp5g_find_far(sock_net(skb->sk), info->attrs);
    if (IS_ERR(far)) {
		printk_ratelimited("%s:%d Failed to find far\n",
				__func__, __LINE__);
        err = PTR_ERR(far);
        goto unlock;
    }

    skb_ack = genlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);
    if (!skb_ack) {
		printk_ratelimited("%s:%d Failed to allocate skb_ack\n",
				__func__, __LINE__);
        err = -ENOMEM;
        goto unlock;
    }

    err = gtp5g_genl_fill_far(skb_ack, 
					NETLINK_CB(skb).portid,
                    info->snd_seq, 
					info->nlhdr->nlmsg_type, 
					far);
    if (err < 0) {
		printk_ratelimited("%s:%d Failed to fill far\n",
				__func__, __LINE__);
        goto freebuf;
	}

    rcu_read_unlock();

    return genlmsg_unicast(genl_info_net(info), skb_ack, info->snd_portid);

freebuf:
    kfree_skb(skb_ack);
unlock:
    rcu_read_unlock();
    return err;
}

static int gtp5g_genl_dump_far(struct sk_buff *skb, struct netlink_callback *cb)
{
    /* netlink_callback->args
     * args[0] : index of gtp5g dev id
     * args[1] : index of gtp5g hash entry id in dev
     * args[2] : index of gtp5g far id
     * args[5] : set non-zero means it is finished
     */
    struct gtp5g_dev *gtp, *last_gtp = (struct gtp5g_dev *)cb->args[0];
    struct net *net = sock_net(skb->sk);
    struct gtp5g_net *gn = net_generic(net, gtp5g_net_id);
    int i, last_hash_entry_id = cb->args[1], ret;
    u32 far_id = cb->args[2];
    struct gtp5g_far *far;

    if (cb->args[5]) {
		printk_ratelimited("%s:%d Failed to dump FAR arg5 present\n", __func__, __LINE__);
        return 0;
	}

    list_for_each_entry_rcu(gtp, &gn->gtp5g_dev_list, list) {
        if (last_gtp && last_gtp != gtp)
            continue;
        else
            last_gtp = NULL;

        for (i = last_hash_entry_id; i < gtp->hash_size; i++) {
            hlist_for_each_entry_rcu(far, &gtp->far_id_hash[i], hlist_id) {
                if (far_id && far_id != far->id)
                    continue;
                else
                    far_id = 0;

                ret = gtp5g_genl_fill_far(skb, 
								NETLINK_CB(cb->skb).portid,
                                cb->nlh->nlmsg_seq, 
								cb->nlh->nlmsg_type, 
								far);
                if (ret < 0) {
                    cb->args[0] = (unsigned long) gtp;
                    cb->args[1] = i;
                    cb->args[2] = far->id;
                    goto out;
                }
            }
        }
    }
    cb->args[5] = 1;

out:
    return skb->len;
}

/** ---------------------------------------------------------------------
 * 								QER
 *  ---------------------------------------------------------------------
 * */
static void qer_context_free(struct rcu_head *head)
{
    struct gtp5g_qer *qer = container_of(head, struct gtp5g_qer, rcu_head);

    if (!qer)
        return;

    kfree(qer);
}

static void qer_context_delete(struct gtp5g_qer *qer)
{
    struct gtp5g_dev *gtp = netdev_priv(qer->dev);
    struct hlist_head *head;
    struct gtp5g_pdr *pdr;

    if (!qer)
        return;

    if (!hlist_unhashed(&qer->hlist_id))
        hlist_del_rcu(&qer->hlist_id);

    head = &gtp->related_qer_hash[u32_hashfn(qer->id) % gtp->hash_size];
    hlist_for_each_entry_rcu(pdr, head, hlist_related_qer) {
        if (*pdr->qer_id == qer->id) {
            pdr->qer = NULL;
            unix_sock_client_delete(pdr);
        }
    }

    call_rcu(&qer->rcu_head, qer_context_free);
}

static int qer_fill(struct gtp5g_qer *qer, struct gtp5g_dev *gtp, struct genl_info *info)
{
    struct nlattr *mbr_param_attrs[GTP5G_QER_MBR_ATTR_MAX + 1];
    struct nlattr *gbr_param_attrs[GTP5G_QER_GBR_ATTR_MAX + 1];
    struct gtp5g_pdr *pdr;
    struct hlist_head *head;

    qer->id = nla_get_u32(info->attrs[GTP5G_QER_ID]);

    if (info->attrs[GTP5G_QER_GATE]) {
        qer->ul_dl_gate = nla_get_u8(info->attrs[GTP5G_QER_GATE]);
    }

	/* MBR */
    if (info->attrs[GTP5G_QER_MBR] &&
        !nla_parse_nested(mbr_param_attrs, GTP5G_QER_MBR_ATTR_MAX, info->attrs[GTP5G_QER_MBR], NULL, NULL)) {
		qer->mbr.ul_high = nla_get_u32(mbr_param_attrs[GTP5G_QER_MBR_UL_HIGH32]);
		qer->mbr.ul_low  = nla_get_u8(mbr_param_attrs[GTP5G_QER_MBR_UL_LOW8]);
		qer->mbr.dl_high = nla_get_u32(mbr_param_attrs[GTP5G_QER_MBR_DL_HIGH32]);
		qer->mbr.dl_low  = nla_get_u8(mbr_param_attrs[GTP5G_QER_MBR_DL_LOW8]);
    }

	/* GBR */
    if (info->attrs[GTP5G_QER_GBR] &&
        !nla_parse_nested(gbr_param_attrs, GTP5G_QER_GBR_ATTR_MAX, info->attrs[GTP5G_QER_GBR], NULL, NULL)) {
		qer->gbr.ul_high = nla_get_u32(gbr_param_attrs[GTP5G_QER_GBR_UL_HIGH32]);
		qer->gbr.ul_low  = nla_get_u8(gbr_param_attrs[GTP5G_QER_GBR_UL_LOW8]);
		qer->gbr.dl_high = nla_get_u32(gbr_param_attrs[GTP5G_QER_GBR_DL_HIGH32]);
		qer->gbr.dl_low  = nla_get_u8(gbr_param_attrs[GTP5G_QER_GBR_DL_LOW8]);
    }

    if (info->attrs[GTP5G_QER_CORR_ID]) {
        qer->qer_corr_id = nla_get_u32(info->attrs[GTP5G_QER_CORR_ID]);
    }

    if (info->attrs[GTP5G_QER_RQI]) {
        qer->rqi = nla_get_u8(info->attrs[GTP5G_QER_RQI]);
    }

    if (info->attrs[GTP5G_QER_QFI]) {
        qer->qfi = nla_get_u8(info->attrs[GTP5G_QER_QFI]);
    }

    if (info->attrs[GTP5G_QER_PPI]) {
        qer->ppi = nla_get_u8(info->attrs[GTP5G_QER_PPI]);
    }

    if (info->attrs[GTP5G_QER_RCSR]) {
        qer->rcsr = nla_get_u8(info->attrs[GTP5G_QER_RCSR]);
    }

    /* Update PDRs which has not linked to this QER */
    head = &gtp->related_qer_hash[u32_hashfn(qer->id) % gtp->hash_size];
    hlist_for_each_entry_rcu(pdr, head, hlist_related_qer) {
        if (*pdr->qer_id == qer->id) {
            pdr->qer = qer;
            if (unix_sock_client_update(pdr) < 0)
                pr_warn("PDR[%u] update fail when QER[%u] apply action is changed",
                    pdr->id, qer->id);
        }
    }

    return 0;
}

static struct gtp5g_qer *qer_find_by_id(struct gtp5g_dev *gtp, u32 id)
{
    struct hlist_head *head;
    struct gtp5g_qer *qer;

    head = &gtp->qer_id_hash[u32_hashfn(id) % gtp->hash_size];
    hlist_for_each_entry_rcu(qer, head, hlist_id) {
        if (qer->id == id)
            return qer;
    }

    return NULL;
}

static int gtp5g_gnl_add_qer(struct gtp5g_dev *gtp, struct genl_info *info)
{

    struct net_device *dev = gtp->dev;
    struct gtp5g_qer *qer;
    int err = 0;
    u32 qer_id;

	if (!dev) {
		printk_ratelimited("Object net_device not found\n");
		return -EEXIST;
	}

    qer_id = nla_get_u32(info->attrs[GTP5G_QER_ID]);
    qer = qer_find_by_id(gtp, qer_id);
    if (qer) {
    	if (info->nlhdr->nlmsg_flags & NLM_F_EXCL)
            return -EEXIST;
        else if (!(info->nlhdr->nlmsg_flags & NLM_F_REPLACE))
            return -EOPNOTSUPP;

        err = qer_fill(qer, gtp, info);
        if (err < 0) {
            qer_context_delete(qer);
            pr_warn("5G GTP update QER_ID(%u) err(%u)\n", qer_id, err);
        } else {
            netdev_dbg(dev, "5G GTP update QER_ID(%u)", qer_id);
        }

        return err;
    }

    if (info->nlhdr->nlmsg_flags & NLM_F_REPLACE) {
		netdev_dbg(dev, "Invalid flage set NLM_F_REPLACE");
        return -ENOENT;
	}

    if (info->nlhdr->nlmsg_flags & NLM_F_APPEND) {
		netdev_dbg(dev, "Invalid flage set NLM_F_APPEND");
        return -EOPNOTSUPP;
	}

    qer = kzalloc(sizeof(*qer), GFP_ATOMIC);
    if (!qer) {
		netdev_dbg(dev, "Failed to allocate memory for QER_ID(%u)", qer_id);
        return -ENOMEM;
    }

    qer->dev = gtp->dev;
    err = qer_fill(qer, gtp, info);
    if (err < 0) {
        netdev_dbg(dev, "5G GTP add QER_ID(%u) fail", qer_id);
        qer_context_delete(qer);
    } else {
        hlist_add_head_rcu(&qer->hlist_id, 
							&gtp->qer_id_hash[u32_hashfn(qer_id) % gtp->hash_size]);
        //printk_ratelimited("%s: Successfully added QER_ID(%u)", __func__, qer_id);
    }

    return err;
}


static int gtp5g_genl_add_qer(struct sk_buff *skb, struct genl_info *info)
{
    struct gtp5g_dev *gtp;
    int err = 0;

    if (!info->attrs[GTP5G_QER_ID] ||
        !info->attrs[GTP5G_LINK]) {
    	printk_ratelimited("%s:%d QER_ID or GTP5g_LINK is not present\n",
				__func__, __LINE__); 
	   	return -EINVAL;
	}

    rtnl_lock();
    rcu_read_lock();

    gtp = gtp5g_find_dev(sock_net(skb->sk), info->attrs);
    if (!gtp) {
		printk_ratelimited("%s:%d Unable to find the gtp device\n", __func__, __LINE__);
        err = -ENODEV;
        goto UNLOCK;
    }

    err = gtp5g_gnl_add_qer(gtp, info);

UNLOCK:
    rcu_read_unlock();
    rtnl_unlock();

    return err;
}

static int gtp5g_genl_del_qer(struct sk_buff *skb, struct genl_info *info)
{
    u32 id;
    struct gtp5g_qer *qer;
    int err = 0;

    if (!info->attrs[GTP5G_QER_ID] ||
        !info->attrs[GTP5G_LINK])
        return -EINVAL;

    id = nla_get_u32(info->attrs[GTP5G_QER_ID]);

    rcu_read_lock();
    qer = gtp5g_find_qer(sock_net(skb->sk), info->attrs);
    if (IS_ERR(qer)) {
        err = PTR_ERR(qer);
        printk_ratelimited("%s: Failed to find qer(%u)\n", __func__, id);
        goto unlock;
    }

    netdev_dbg(qer->dev, "5G GTP-U : delete QER id(%u)\n", id);
    qer_context_delete(qer);
unlock:
    rcu_read_unlock();
    return err;
}

static int gtp5g_genl_fill_qer(struct sk_buff *skb, u32 snd_portid, u32 snd_seq,
                               u32 type, struct gtp5g_qer *qer)
{
    void *genlh;
    int cnt;
    struct nlattr *nest_mbr_param, *nest_gbr_param;
    struct gtp5g_dev *gtp = netdev_priv(qer->dev);
    struct hlist_head *head;
    struct gtp5g_pdr *pdr;

    u16 *u16_buf = kzalloc(0xff * sizeof(u16), GFP_KERNEL);
	if (!u16_buf) {
		printk_ratelimited("%s:%d Failed to allocated mmeory\n", __func__,
				__LINE__);
		return -EMSGSIZE;
	}

    genlh = genlmsg_put(skb, snd_portid, snd_seq, 
						&gtp5g_genl_family, 0, type);
    if (!genlh) {
		printk_ratelimited("%s:%d Failed to get genlh snd_port_id(%#x)"
				" \t snd_seq(%#x) type(%#x)\n", __func__, __LINE__, 
				snd_portid, snd_seq, type);
        goto genlmsg_fail;
	}

	/* QER_ID & GATE */
	if (nla_put_u32(skb, GTP5G_QER_ID, qer->id) ||
		nla_put_u8(skb, GTP5G_QER_GATE, qer->ul_dl_gate))
        goto genlmsg_fail;

	/* MBR */
	if (!(nest_mbr_param = nla_nest_start(skb, GTP5G_QER_MBR)))
		goto genlmsg_fail;

	if (nla_put_u32(skb, GTP5G_QER_MBR_UL_HIGH32, qer->mbr.ul_high) ||
		nla_put_u8(skb, GTP5G_QER_MBR_UL_LOW8, qer->mbr.ul_low) ||
		nla_put_u32(skb, GTP5G_QER_MBR_DL_HIGH32, qer->mbr.dl_high) ||
		nla_put_u8(skb, GTP5G_QER_MBR_DL_LOW8, qer->mbr.dl_low))
        goto genlmsg_fail;

    nla_nest_end(skb, nest_mbr_param);

	/* GBR */
	if (!(nest_gbr_param = nla_nest_start(skb, GTP5G_QER_GBR)))
		goto genlmsg_fail;

	if (nla_put_u32(skb, GTP5G_QER_GBR_UL_HIGH32, qer->gbr.ul_high) ||
		nla_put_u8(skb, GTP5G_QER_GBR_UL_LOW8, qer->gbr.ul_low) ||
		nla_put_u32(skb, GTP5G_QER_GBR_DL_HIGH32, qer->gbr.dl_high) ||
		nla_put_u8(skb, GTP5G_QER_GBR_DL_LOW8, qer->gbr.dl_low))
        goto genlmsg_fail;

    nla_nest_end(skb, nest_gbr_param);

	/* CORR_ID, RQI, QFI, PPI, RCSR */
    if (nla_put_u32(skb, GTP5G_QER_CORR_ID, qer->qer_corr_id) ||
		nla_put_u8(skb, GTP5G_QER_RQI, qer->rqi) ||
		nla_put_u8(skb, GTP5G_QER_QFI, qer->qfi) ||
		nla_put_u8(skb, GTP5G_QER_PPI, qer->ppi) ||
		nla_put_u8(skb, GTP5G_QER_RCSR, qer->rcsr))
        goto genlmsg_fail;

    cnt = 0;    
    head = &gtp->related_qer_hash[u32_hashfn(qer->id) % gtp->hash_size];
    hlist_for_each_entry_rcu(pdr, head, hlist_related_qer) {
        if (cnt >= 0xff)
            goto genlmsg_fail;

        if (*pdr->qer_id == qer->id)
            u16_buf[cnt++] = pdr->id;
    }

    if (cnt) {
        if (nla_put(skb, 
					GTP5G_QER_RELATED_TO_PDR,
            		(cnt * sizeof(u16) / sizeof(char)), 
					u16_buf))
            goto genlmsg_fail;
    }

    kfree(u16_buf);
    genlmsg_end(skb, genlh);
    return 0;

genlmsg_fail:
    kfree(u16_buf);
    genlmsg_cancel(skb, genlh);
    return -EMSGSIZE;
}

static struct gtp5g_qer *gtp5g_find_qer_by_link(struct net *net, struct nlattr *nla[])
{
    struct gtp5g_dev *gtp;

    gtp = gtp5g_find_dev(net, nla);
    if (!gtp)
        return ERR_PTR(-ENODEV);

    if (nla[GTP5G_QER_ID]) {
        u32 id = nla_get_u32(nla[GTP5G_QER_ID]);
        return qer_find_by_id(gtp, id);
    }

    return ERR_PTR(-EINVAL);
}

static struct gtp5g_qer *gtp5g_find_qer(struct net *net, struct nlattr *nla[])
{
    struct gtp5g_qer *qer;

    if (nla[GTP5G_LINK])
        qer = gtp5g_find_qer_by_link(net, nla);
    else
        qer = ERR_PTR(-EINVAL);

    if (!qer)
        qer = ERR_PTR(-ENOENT);

    return qer;
}

static int gtp5g_genl_get_qer(struct sk_buff *skb, struct genl_info *info)
{
    struct gtp5g_qer *qer;
    struct sk_buff *skb_ack;
    int err;

    if (!info->attrs[GTP5G_QER_ID]) {
		printk_ratelimited("%s:%d QER ID is not present\n", __func__, __LINE__);
        return -EINVAL;
	}

    rcu_read_lock();

    qer = gtp5g_find_qer(sock_net(skb->sk), info->attrs);
    if (IS_ERR(qer)) {
		printk_ratelimited("%s:%d Failed to find QER\n", __func__, __LINE__);
        err = PTR_ERR(qer);
        goto unlock;
    }

    skb_ack = genlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);
    if (!skb_ack) {
        err = -ENOMEM;
        goto unlock;
    }

    err = gtp5g_genl_fill_qer(skb_ack, 
								NETLINK_CB(skb).portid,
                              	info->snd_seq, 
								info->nlhdr->nlmsg_type, 
								qer);
    if (err < 0) {
		printk_ratelimited("%s:%d Failed to fil the qer\n", __func__, __LINE__);
        goto freebuf;
	}

    rcu_read_unlock();
    return genlmsg_unicast(genl_info_net(info), skb_ack, info->snd_portid);

freebuf:
    kfree_skb(skb_ack);
unlock:
    rcu_read_unlock();
    return err;
}

static int gtp5g_genl_dump_qer(struct sk_buff *skb, struct netlink_callback *cb)
{
    /* netlink_callback->args
     * args[0] : index of gtp5g dev id
     * args[1] : index of gtp5g hash entry id in dev
     * args[2] : index of gtp5g qer id
     * args[5] : set non-zero means it is finished
     */
    struct gtp5g_dev *gtp, *last_gtp = (struct gtp5g_dev *)cb->args[0];
    struct net *net = sock_net(skb->sk);
    struct gtp5g_net *gn = net_generic(net, gtp5g_net_id);
    int i, last_hash_entry_id = cb->args[1], ret;
    u32 qer_id = cb->args[2];
    struct gtp5g_qer *qer;

    if (cb->args[5]) {
		printk_ratelimited("%s:%d Invalid args\n", __func__, __LINE__);
        return 0;
	}

    list_for_each_entry_rcu(gtp, &gn->gtp5g_dev_list, list) {
        if (last_gtp && last_gtp != gtp)
            continue;
        else
            last_gtp = NULL;

        for (i = last_hash_entry_id; i < gtp->hash_size; i++) {
            hlist_for_each_entry_rcu(qer, &gtp->qer_id_hash[i], hlist_id) {
                if (qer_id && qer_id != qer->id)
                    continue;
                else
                    qer_id = 0;

                ret = gtp5g_genl_fill_qer(skb, 
											NETLINK_CB(cb->skb).portid,
                                        	cb->nlh->nlmsg_seq, 
											cb->nlh->nlmsg_type, 
											qer);
                if (ret < 0) {
                    cb->args[0] = (unsigned long) gtp;
                    cb->args[1] = i;
                    cb->args[2] = qer->id;
                    goto out;
                }
            }
        }
    }

    cb->args[5] = 1;

out:
    return skb->len;
}

static const struct nla_policy gtp5g_genl_pdr_policy[GTP5G_PDR_ATTR_MAX + 1] = {
    [GTP5G_PDR_ID]                              = { .type = NLA_U32, },
    [GTP5G_PDR_PRECEDENCE]                      = { .type = NLA_U32, },
    [GTP5G_PDR_PDI]                             = { .type = NLA_NESTED, },
    [GTP5G_OUTER_HEADER_REMOVAL]                = { .type = NLA_U8, },
    [GTP5G_PDR_FAR_ID]                          = { .type = NLA_U32, },
    [GTP5G_PDR_QER_ID]                          = { .type = NLA_U32, },
};

static const struct nla_policy gtp5g_genl_far_policy[GTP5G_FAR_ATTR_MAX + 1] = {
    [GTP5G_FAR_ID]                              = { .type = NLA_U32, },
    [GTP5G_FAR_APPLY_ACTION]                    = { .type = NLA_U8, },
    [GTP5G_FAR_FORWARDING_PARAMETER]            = { .type = NLA_NESTED, },
};

static const struct nla_policy gtp5g_genl_qer_policy[GTP5G_QER_ATTR_MAX + 1] = {
    [GTP5G_QER_ID]                              = { .type = NLA_U32, },
    [GTP5G_QER_GATE]                            = { .type = NLA_U8, },
    [GTP5G_QER_MBR]                             = { .type = NLA_NESTED, },
    [GTP5G_QER_GBR]                             = { .type = NLA_NESTED, },
    [GTP5G_QER_CORR_ID]                     	= { .type = NLA_U32, },
    [GTP5G_QER_RQI]                             = { .type = NLA_U8, },
    [GTP5G_QER_QFI]                             = { .type = NLA_U8, },
    [GTP5G_QER_PPI]                             = { .type = NLA_U8, },
    [GTP5G_QER_RCSR]                            = { .type = NLA_U8, },
};

static const struct genl_ops gtp5g_genl_ops[] = {
    {
        .cmd = GTP5G_CMD_ADD_PDR,
        // .validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
        .doit = gtp5g_genl_add_pdr,
        // .policy = gtp5g_genl_pdr_policy,
        .flags = GENL_ADMIN_PERM,
    },
    {
        .cmd = GTP5G_CMD_DEL_PDR,
        // .validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
        .doit = gtp5g_genl_del_pdr,
        // .policy = gtp5g_genl_pdr_policy,
        .flags = GENL_ADMIN_PERM,
    },
    {
        .cmd = GTP5G_CMD_GET_PDR,
        // .validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
        .doit = gtp5g_genl_get_pdr,
        .dumpit = gtp5g_genl_dump_pdr,
        // .policy = gtp5g_genl_pdr_policy,
        .flags = GENL_ADMIN_PERM,
    },
    {
        .cmd = GTP5G_CMD_ADD_FAR,
        // .validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
        .doit = gtp5g_genl_add_far,
        // .policy = gtp5g_genl_far_policy,
        .flags = GENL_ADMIN_PERM,
    },
    {
        .cmd = GTP5G_CMD_DEL_FAR,
        // .validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
        .doit = gtp5g_genl_del_far,
        // .policy = gtp5g_genl_far_policy,
        .flags = GENL_ADMIN_PERM,
    },
    {
        .cmd = GTP5G_CMD_GET_FAR,
        // .validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
        .doit = gtp5g_genl_get_far,
        .dumpit = gtp5g_genl_dump_far,
        // .policy = gtp5g_genl_far_policy,
        .flags = GENL_ADMIN_PERM,
    },
	{
        .cmd = GTP5G_CMD_ADD_QER,
        // .validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
        .doit = gtp5g_genl_add_qer,
        // .policy = gtp5g_genl_qer_policy,
        .flags = GENL_ADMIN_PERM,
    },
    {
        .cmd = GTP5G_CMD_DEL_QER,
        // .validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
        .doit = gtp5g_genl_del_qer,
        // .policy = gtp5g_genl_qer_policy,
        .flags = GENL_ADMIN_PERM,
    },
    {
        .cmd = GTP5G_CMD_GET_QER,
        // .validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
        .doit = gtp5g_genl_get_qer,
        .dumpit = gtp5g_genl_dump_qer,
        // .policy = gtp5g_genl_qer_policy,
        .flags = GENL_ADMIN_PERM,
    },

};

static struct genl_family gtp5g_genl_family __ro_after_init = {
    .name       = "gtp5g",
    .version    = 0,
    .hdrsize    = 0,
    .maxattr    = GTP5G_ATTR_MAX,
    .netnsok    = true,
    .module     = THIS_MODULE,
    .ops        = gtp5g_genl_ops,
    .n_ops      = ARRAY_SIZE(gtp5g_genl_ops),
};

static int __net_init gtp5g_net_init(struct net *net)
{
    struct gtp5g_net *gn = net_generic(net, gtp5g_net_id);

    INIT_LIST_HEAD(&gn->gtp5g_dev_list);
    return 0;
}

static void __net_exit gtp5g_net_exit(struct net *net)
{
    struct gtp5g_net *gn = net_generic(net, gtp5g_net_id);
    struct gtp5g_dev *gtp;
    LIST_HEAD(list);

    rtnl_lock();
    list_for_each_entry(gtp, &gn->gtp5g_dev_list, list)
        gtp5g_dellink(gtp->dev, &list);

    unregister_netdevice_many(&list);
    rtnl_unlock();
}

static struct pernet_operations gtp5g_net_ops = {
    .init    = gtp5g_net_init,
    .exit    = gtp5g_net_exit,
    .id      = &gtp5g_net_id,
    .size    = sizeof(struct gtp5g_net),
};

static int __init gtp5g_init(void)
{
    int err;

    get_random_bytes(&gtp5g_h_initval, sizeof(gtp5g_h_initval));

    err = rtnl_link_register(&gtp5g_link_ops);
    if (err < 0)
        goto error_out;

    err = genl_register_family(&gtp5g_genl_family);
    if (err < 0)
        goto unreg_rtnl_link;

    err = register_pernet_subsys(&gtp5g_net_ops);
    if (err < 0)
        goto unreg_genl_family;

    pr_info("5G GTP module loaded (pdr ctx size %zd bytes)\n",
        sizeof(struct gtp5g_pdr));

    return 0;

unreg_genl_family:
    genl_unregister_family(&gtp5g_genl_family);
unreg_rtnl_link:
    rtnl_link_unregister(&gtp5g_link_ops);
error_out:
    pr_err("error loading 5G GTP module loaded\n");
    return err;
}
late_initcall(gtp5g_init);

static void __exit gtp5g_fini(void)
{
    genl_unregister_family(&gtp5g_genl_family);
    rtnl_link_unregister(&gtp5g_link_ops);
    unregister_pernet_subsys(&gtp5g_net_ops);

    pr_info("5G GTP module unloaded\n");
}
module_exit(gtp5g_fini);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yao-Wen Chang <yaowenowo@gmail.com>");
MODULE_DESCRIPTION("Interface for 5G GTP encapsulated traffic");
MODULE_VERSION(DRV_VERSION);
MODULE_ALIAS_RTNL_LINK("gtp5g");
MODULE_ALIAS_GENL_FAMILY("gtp5g");
