// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Tesla Inc. All rights reserved.
 *
 * TTP-GW      A sample implementation of Tesla Transport Protocol Gateway (TTP-GW) that works with
 *             a network of Linux machines running the TTPoE kernel module and provides a way to
 *             allow islands of TTPoE in separate Layer-2 Ethernet networks to function seamlessly
 *             over an IPv4 network. This is work under development.
 *
 *             This public release of the TTP software implementation is aligned with the patent
 *             disclosure and public release of the main TTP Protocol specification. Users of
 *             this software module must take into consideration those disclosures in addition
 *             to the license agreement mentioned here.
 *
 * Authors:    Diwakar Tundlam <dntundlam@tesla.com>
 *
 * This software is licensed under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, and may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * Without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 */

#ifndef MODULE
#define MODULE
#endif

#ifndef __KERNEL__
#define __KERNEL__
#endif

#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <linux/inet.h>
#include <linux/etherdevice.h>
#include <linux/inetdevice.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>

#include <net/arp.h>
#include <net/ip.h>
#include <net/route.h>
#include <net/neighbour.h>

#include <net/ndisc.h>
#include <net/ip6_route.h>
#include <uapi/linux/ipv6.h>

#include <ttp.h>

#include "ttpip.h"


char *ttp_dev;
int ttp_verbose = -1;
int ttp_shutdown = 1;         /* 'DOWN' by default - enabled at init after checking */

u32 Tesla_Mac_Oui = TESLA_MAC_OUI; /* CAUTION: hard-code main OUI (won't work with OUI-#2) */

static struct timer_list ttp_nh_mac_timer_head;
static struct timer_list ttp_gw_mac_adv_timer_head;

static int ttpip_pkt_recv (struct sk_buff *skb, struct net_device *dev,
                           struct packet_type *ptype, struct net_device *odev);
static int ttpip_frm_recv (struct sk_buff *skb, struct net_device *dev,
                           struct packet_type *ptype, struct net_device *odev);

static struct packet_type ttpip_etype_lyr3 __read_mostly = {
    .dev  = NULL,               /* set via module-param */
    .type = 0,                  /* htons (ETH_P_IP | ETH_P_IPV6) */
    .func = ttpip_pkt_recv,
    .ignore_outgoing = true,
};
static struct packet_type ttpip_etype_tsla __read_mostly = {
    .dev  = NULL,               /* set via module-param */
    .type = htons (TESLA_ETH_P_TTPOE),
    .func = ttpip_frm_recv,
    .ignore_outgoing = true,
};

static u16 ttp_myzn;
static int ttp_num_gwips, ttp_num_edevs, ttp_num_intfs;

struct ttp_intf_cfg ttp_zones[TTP_MAX_NUM_ZONES];
struct ttp_intf_cfg ttp_edevs[TTP_MAX_NUM_EDEVS];
struct ttp_intf_cfg ttp_intfs[TTP_MAX_NUM_INTFS];

struct mutex        ttp_mactable_mutx;
struct rb_root      ttp_mactbl_rbroot = RB_ROOT;
static unsigned int ttp_mactbl_ct;

/* Helper macro to handle snprintf overflow and errors.
 * This requires variables: 'buf' 'bs' 'sc' to exist. */
#define TTP_SNPRINTF(arg...)                        \
    do {                                            \
        int nn = snprintf (buf + sc, bs - sc, arg); \
        if ((nn) < 0 || (nn) >= bs - sc) {          \
            return sc;                              \
        } sc += (nn);                               \
    } while (0)


static struct sk_buff *ttpip_skb_aloc (void)
{
    struct sk_buff *skb;
    u16 frame_len;

    frame_len = ETH_HLEN + 12;

    if (!(skb = alloc_skb (frame_len + TTP_IP_HEADROOM, GFP_KERNEL))) {
        return NULL;
    }

    skb_reserve (skb, TTP_IP_HEADROOM);
    skb_reset_mac_header (skb);
    skb_set_network_header (skb, ETH_HLEN);

    skb->len = max (frame_len, TTP_MIN_FRAME_LEN);
    skb_trim (skb, skb->len);
    skb_set_tail_pointer (skb, skb->len);

    return skb;
}


static void ttpip_pretty_print_data (const u8 *caption, const int bpl, bool tx,
                                     const u8 *devname, const u8 *buf, const int buflen)
{
    int len = buflen;

    if (ttp_verbose < 2) {
        return;
    }
    TTP_DBG ("%s %s dev: %s len: %d\n", caption, tx ? "<<- Tx" : "->> Rx", devname, buflen);
    do {
        TTP_DBG ("%s %*ph\n", caption, min (len, 16), buf);
        buf += 16;
        len -= 16;
    } while (len > 0);
}


static inline void ttp_print_ipv4_hdr (struct iphdr *ip)
{
    if (ttp_verbose) {
        TTP_DBG ("ip4h: %*ph\n", 10, ip);
        TTP_DBG ("      %*ph\n", (int)sizeof (*ip) - 10, (10 + (u8 *)ip));
        TTP_DBG ("  ver:%d ihl:%d ttl:%d tos:%02x len:%d proto:%d%s\n",
                 ip->version, ip->ihl, ip->ttl, ip->tos, ntohs (ip->tot_len),
                 ip->protocol, ip->protocol == IPPROTO_TTP ? " (TTP)" : "");
        TTP_DBG (" dip4:%pI4 sip4:%pI4\n", &ip->daddr, &ip->saddr);
    }
}


static inline void ttp_print_ipv6_hdr (struct ipv6hdr *ipv6)
{
    if (ttp_verbose) {
        TTP_DBG ("ip6h: %*ph\n", 20, ipv6);
        TTP_DBG ("      %*ph\n", (int)sizeof (*ipv6) - 20, (20 + (u8 *)ipv6));
        TTP_DBG ("  ver:%d len:%d ttl:%d proto:%d%s\n",
                 ipv6->version, ntohs (ipv6->payload_len), ipv6->hop_limit,
                 ipv6->nexthdr, ipv6->nexthdr == IPPROTO_TTP ? " (TTP)" : "");
        TTP_DBG (" dip6:%pI6c sip6:%pI6c\n", &ipv6->daddr, &ipv6->saddr);
    }
}


static inline struct ttp_intf_cfg *ttp_intf_cfg_get (int zn)
{
    struct ttp_intf_cfg *zcfg;

    if (zn > 0 && zn < TTP_MAX_NUM_ZONES) {
        zcfg = &ttp_zones[zn];
        if (zcfg->ver == 4 || zcfg->ver == 6) {
            return zcfg;
        }
    }

    return NULL;
}


static struct ttp_intf_cfg *ttp_intf_get (struct ttp_intf_cfg *zf, int ver)
{
    int iv;
    struct ttp_intf_cfg *intf, *intf_only_ver = NULL;

    for (iv = 0; iv < ttp_num_intfs; iv++) {
        intf = &ttp_intfs[iv];
        if (intf->ver != ver) {
            continue;
        }
        if (intf->dev == zf->dev) {
            return intf;
        }
        else if (!intf_only_ver) {
            intf_only_ver = intf;
        }
    }
    return intf_only_ver;
}


static int ttp_gw_ipv4_get (struct in_addr *ip4)
{
    int zn;
    struct ttp_intf_cfg *zcfg;

    for (zn = 1; zn < TTP_MAX_NUM_ZONES; zn++) {
        zcfg = &ttp_zones[zn];
        if (zcfg->ver != 4) {
            continue;
        }
        if (zcfg->ip4.s_addr == ip4->s_addr) {
            return zn;
        }
    }
    return -EINVAL;
}


static int ttp_gw_ipv6_get (struct in6_addr *ip6)
{
    int zn;
    struct ttp_intf_cfg *zcfg;

    for (zn = 1; zn < TTP_MAX_NUM_ZONES; zn++) {
        zcfg = &ttp_zones[zn];
        if (zcfg->ver != 6) {
            continue;
        }
        if (0 == ipv6_addr_cmp (&zcfg->ip6, ip6)) {
            return zn;
        }
    }
    return -EINVAL;
}


static int ttp_param_dummy_set (const char *val, const struct kernel_param *kp)
{
    TTP_LOG ("%s: Error: kernel param not settable\n", __FUNCTION__);
    return -EPERM;
}


static int ttp_param_gwips_set (const char *val, const struct kernel_param *kp)
{
    int len, rv;
    u16 zn;
    char save;
    struct ttp_intf_cfg *zcfg;

    if (!(len = strcspn (val, "\n"))) {
        return 0;
    }
    if (((char *)val)[len] == '\n') {
        ((char *)val)[len] = '\0'; /* eat any trailing newline in val */
    }

    ttp_num_gwips = 0;
    for (zn = 1; zn < TTP_MAX_NUM_ZONES; zn++) {
        zcfg = &ttp_zones[zn];
        len = strcspn (val, ",");
        if (!len) {
            goto next;
        }
        save = val[len];
        if (save == ',') {
            ((char *)val)[len] = '\0'; /* eat any trailing newline in val */
        }
        if ((rv = in4_pton (val, -1, (u8 *)&zcfg->ip4, -1, NULL))) {
            zcfg->ver = 4;
            zcfg->zon = zn;
        }
        else if ((rv = in6_pton (val, -1, (u8 *)&zcfg->ip6, -1, NULL))) {
            zcfg->ver = 6;
            zcfg->zon = zn;
        }
        else {
            goto next;
        }
        ttp_num_gwips++;
        if (zcfg->ver == 4) {
            TTP_DBG ("%s: zn:%d ip4:%pI4\n", __FUNCTION__, zn, &zcfg->ip4);
        }
        else if (zcfg->ver == 6) {
            TTP_DBG ("%s: zn:%d ip6:%pI6c\n", __FUNCTION__, zn, &zcfg->ip6);
        }

    next:
        val += len + 1;
        if ((save == ',') && (zn == TTP_MAX_NUM_ZONES - 1)) {
            TTP_LOG ("%s: ignoring zones beyond max=%d\n", __FUNCTION__,
                     TTP_MAX_NUM_ZONES);
            break;
        }
        if (save != ',') {
            break;
        }
    }
    if (!ttp_num_gwips) {
        return -EINVAL;
    }

    BUG_ON (ttp_num_gwips >= TTP_MAX_NUM_ZONES);
    return 0;
}

static int ttp_param_gwips_get (char *buf, const struct kernel_param *kp)
{
    int zn, sc = 0, bs = PAGE_SIZE;
    struct ttp_intf_cfg *zcfg;
    char ipaddr_str[64], *via;

    BUG_ON (!ttp_num_gwips);
    TTP_SNPRINTF (BLUE "%2s %29s  %-17s  %-8s %s\n" CLEAR,
                  "zn", "ttp-layer3-gateway-ip", "next-hop-mac-addr", "device", "via");

    for (zn = 1; zn < TTP_MAX_NUM_ZONES; zn++) {
        zcfg = &ttp_zones[zn];
        if (!zcfg->ver) {
            continue;
        }
        if (zcfg->ver == 4) {
            snprintf (ipaddr_str, 64, "%26pI4", &zcfg->ip4);
            via = zcfg->gwy ? "rt4" : "dir";
        }
        else if (zcfg->ver == 6) {
            snprintf (ipaddr_str, 64, "%26pI6c", &zcfg->ip6);
            via = zcfg->gwy ? "rt6" : "dir";
        }
        else {
            continue;
        }
        TTP_SNPRINTF ("%s%d%c %26s/%-2d  %*pM  %-8s %s\n" CLEAR,
                      zn == ttp_myzn ? GREEN : NOCOLOR,
                      zn, zn == ttp_myzn ? '*' : ' ',
                      ipaddr_str, zcfg->pfl, ETH_ALEN, zcfg->mac,
                      zcfg->dev->name, zn == ttp_myzn ? "*zn" : via);
    }
    return sc;
}

static const struct kernel_param_ops ttp_param_gwips_ops = {
    .set = ttp_param_gwips_set,
    .get = ttp_param_gwips_get,
};

module_param_cb (gwips, &ttp_param_gwips_ops, &ttp_num_gwips, 0444);
MODULE_PARM_DESC (gwips, "    set list of ttp gateway ip-addreses per zone (1,2,3,..):\n"
                  "                          e.g. gwips=10.0.1.1,10.0.2.2,10.0.3.3,..");


static int ttp_param_intfs_get (char *buf, const struct kernel_param *kp)
{
    int iv, sc = 0, bs = PAGE_SIZE;
    struct ttp_intf_cfg *dev;
    char ipaddr_str[64], zc, st;

    TTP_SNPRINTF (BLUE "%2s %2s  %-8s %29s  %17s\n" CLEAR,
                  "zn", "if", "device", "interface-ip-address", "device-mac-addr");

    for (iv = 0; iv < ttp_num_intfs; iv++) {
        dev = &ttp_intfs[iv];
        zc = st = ' ';
        if (!dev->dev) {
            TTP_SNPRINTF (GRAY "%c%c %2d  %-8s\n" CLEAR, zc, st, iv + 1, "none");
            continue;
        }
        if (dev->zon == ttp_myzn) {
            zc = ttp_myzn + '0';
            st = '*';
        }
        if (dev->ver == 4) {
            snprintf (ipaddr_str, 64, "%26pI4", &dev->ip4);
        }
        else if (dev->ver == 6) {
            snprintf (ipaddr_str, 64, "%26pI6c", &dev->ip6);
        }
        else {
            continue;
        }
        TTP_SNPRINTF ("%s%c%c %2d  %-8s %26s/%-2d  %*pM\n" CLEAR,
                      dev->zon == ttp_myzn ? GREEN : NOCOLOR,
                      zc, st, iv, dev->dev->name, ipaddr_str, dev->pfl,
                      ETH_ALEN, dev->dev->dev_addr);
    }
    return sc;
}

static const struct kernel_param_ops ttp_param_intfs_ops = {
    .set = ttp_param_dummy_set, /* not settable */
    .get = ttp_param_intfs_get,
};

module_param_cb (intfs, &ttp_param_intfs_ops, NULL, 0444);
MODULE_PARM_DESC (intfs, "    get all interfaces on the ttp-gateway");


static int ttp_param_edevs_get (char *buf, const struct kernel_param *kp)
{
    int iv, sc = 0, bs = PAGE_SIZE;
    struct ttp_intf_cfg *dev;

    TTP_SNPRINTF (BLUE "%2s  %-8s %17s\n" CLEAR, "if", "device", "device-mac-addr");

    for (iv = 0; iv < ttp_num_edevs; iv++) {
        dev = &ttp_edevs[iv];
        if (!dev->dev) {
            TTP_SNPRINTF ("%2d %-8s\n", iv, "none");
            continue;
        }
        TTP_SNPRINTF ("%s%-2d  %-8s %*pM\n" CLEAR,
                      !strncmp (dev->dev->name, ttp_dev, 8) ? RED : NOCOLOR, iv,
                      dev->dev->name, ETH_ALEN, dev->dev->dev_addr);
    }
    return sc;
}

static const struct kernel_param_ops ttp_param_edevs_ops = {
    .set = ttp_param_dummy_set, /* not settable */
    .get = ttp_param_edevs_get,
};

module_param_cb (edevs, &ttp_param_edevs_ops, NULL, 0444);
MODULE_PARM_DESC (edevs, "    get all devices on the ttp-gateway");


static const struct kernel_param_ops ttp_param_dev_ops = {
    .set = param_set_charp,
    .get = param_get_charp,
};

/* read-only parameters must be set at module-load */
module_param_cb (dev, &ttp_param_dev_ops, &ttp_dev, 0444);
MODULE_PARM_DESC (dev, "      ttp device name (required at module-load)");


/* returns -1 if m1 < m2, 1 if '>', and 0 when equal */
static int ttp_mactbl_rbtree_cmp (const u8 *m1, const u8 *m2)
{
    u8 t1, t2;

    if (m1 == m2) { /* both NULL is possible */
        return 0;
    }
    /* NULL is lesser */
    if (!m1) {
        return -1;
    }
    if (!m2) {
        return 1;
    }

    /* keep hash-vals in ascending order */
    t1 = ttp_tag_index_hash_calc (m1);
    t2 = ttp_tag_index_hash_calc (m2);
    if (t1 < t2) {
        return 1;
    }
    else if (t1 > t2) {
        return -1;
    }
    /* hash-vals equal */
    return memcmp (m1, m2, ETH_ALEN);
}

static struct ttp_mactable *ttp_mactbl_rbtree_add (const u8 *mac)
{
    struct rb_node **new, *parent = NULL;
    struct ttp_mactable *lmc;
    int cmp;

    if (!mutex_trylock (&ttp_mactable_mutx)) {
        TTP_LOG ("%s: Error: trylock failed [mac %*pM]\n", __FUNCTION__,
                 ETH_ALEN, mac);
        return NULL;
    }

    new = &ttp_mactbl_rbroot.rb_node;
    while (*new) {
        parent = *new;
        lmc = rb_entry (*new, struct ttp_mactable, rbn);

        if ((cmp = ttp_mactbl_rbtree_cmp (lmc->mac, mac)) < 0) {
            new = &((*new)->rb_left);
        }
        else if (cmp > 0) {
            new = &((*new)->rb_right);
        }
        else { /* keys are equal - already exists => lmc */
            goto end;
        }
    }

    lmc = NULL;
    if (ttp_mactbl_ct >= TTP_MAC_TABLE_SIZE) {
        TTP_LOG ("%s: Error: table full(%d) [mac %*pM]\n", __FUNCTION__,
                 ttp_mactbl_ct, ETH_ALEN, mac);
        goto end;
    }
    if (!(lmc = kzalloc(sizeof(*lmc), GFP_KERNEL))) {
        TTP_LOG ("%s: Error: kzalloc failed [mac %*pM]\n", __FUNCTION__,
                 ETH_ALEN, mac);
        goto end;
    }

    lmc->val = 1;
    rb_link_node (&lmc->rbn, parent, new);
    rb_insert_color (&lmc->rbn, &ttp_mactbl_rbroot);

    ttp_mactbl_ct++;
    ether_addr_copy(lmc->mac, mac);

end:
    mutex_unlock (&ttp_mactable_mutx);
    return lmc;
}

static void ttp_mactbl_rbtree_del (const u8 *mac)
{
    struct rb_node **new, *parent = NULL;
    struct ttp_mactable *lmc;
    int cmp;

    if (!mutex_trylock (&ttp_mactable_mutx)) {
        TTP_LOG ("%s: Error: trylock failed [mac %*pM]\n", __FUNCTION__,
                 ETH_ALEN, mac);
        return;
    }

    new = &ttp_mactbl_rbroot.rb_node;
    while (*new) {
        parent = *new;
        lmc = rb_entry (*new, struct ttp_mactable, rbn);

        if ((cmp = ttp_mactbl_rbtree_cmp (lmc->mac, mac)) < 0) {
            new = &((*new)->rb_left);
        }
        else if (cmp > 0) {
            new = &((*new)->rb_right);
        }
        else { /* keys are equal */
            ttp_mactbl_ct--;
            rb_erase (&lmc->rbn, &ttp_mactbl_rbroot);
            kfree (lmc);
            break;
        }
    }

    mutex_unlock (&ttp_mactable_mutx);
}

static struct ttp_mactable *ttp_mactbl_rbtree_get (const u8 *mac)
{
    struct rb_node **new, *parent = NULL;
    struct ttp_mactable *lmc;
    int cmp;

    if (!mutex_trylock (&ttp_mactable_mutx)) {
        TTP_LOG ("%s: Error: trylock failed [mac %*pM]\n", __FUNCTION__,
                 ETH_ALEN, mac);
        return NULL;
    }

    new = &ttp_mactbl_rbroot.rb_node;
    while (*new) {
        parent = *new;
        lmc = rb_entry (*new, struct ttp_mactable, rbn);

        if ((cmp = ttp_mactbl_rbtree_cmp (lmc->mac, mac)) < 0) {
            new = &((*new)->rb_left);
        }
        else if (cmp > 0) {
            new = &((*new)->rb_right);
        }
        else { /* found it => lmc */
            goto end;
        }
    }
    lmc = NULL;

end:
    mutex_unlock (&ttp_mactable_mutx);
    return lmc;
}


static struct ttp_mactable *ttp_mactbl_rbtree_get_next (const struct ttp_mactable *mct)
{
    struct rb_node *rb = !mct ? rb_first (&ttp_mactbl_rbroot) : rb_next (&mct->rbn);

    return rb ? rb_entry (rb, struct ttp_mactable, rbn) : NULL;
}

static struct ttp_mactable *ttp_mactbl_find (const char *mac)
{
    return ttp_mactbl_rbtree_get (mac);
}


/*
 * Fills out ipv6 header in skb with gw-config from zcfg and
 * returns a pointer to the next header - tesla_shim
 */
static struct ttp_tsla_shim_hdr *ttp_prepare_ipv4 (u8 *pkt, u16 len, struct ttp_intf_cfg *zcfg)
{
    u16 frame_len;
    struct ttp_intf_cfg *intf;
    struct iphdr *ipv4 = (struct iphdr *)pkt;

    memset (ipv4, 0, sizeof (*ipv4));
    ipv4->version = 4;
    ipv4->ihl = 5;
    ipv4->ttl = 9;
    ipv4->protocol = IPPROTO_TTP;

    if (!(intf = ttp_intf_get (zcfg, 4))) {
        return NULL;
    }

    ipv4->saddr = intf->ip4.s_addr;
    ipv4->daddr = zcfg->ip4.s_addr;
    frame_len = ETH_HLEN + sizeof (struct iphdr) + len;
    frame_len = max (frame_len, TTP_MIN_FRAME_LEN);
    ipv4->tot_len = htons (frame_len - ETH_HLEN);
    ipv4->check = ip_fast_csum ((unsigned char *)ipv4, ipv4->ihl);

    ttp_print_ipv4_hdr (ipv4);

    return (struct ttp_tsla_shim_hdr *)(ipv4 + 1);
}


/*
 * Fills out ipv6 header in skb with gw-config from zcfg and
 * returns a pointer to the next header - tesla_shim
 */
static struct ttp_tsla_shim_hdr *ttp_prepare_ipv6 (u8 *pkt, u16 len, struct ttp_intf_cfg *zcfg)
{
    u16 frame_len;
    struct ipv6hdr *ipv6 = (struct ipv6hdr *)pkt;
    struct ttp_intf_cfg *intf;

    memset (ipv6, 0, sizeof (*ipv6));
    ipv6->version = 6;
    ipv6->nexthdr = IPPROTO_TTP;
    ipv6->hop_limit = 9;

    if (!(intf = ttp_intf_get (zcfg, 6))) {
        return NULL;
    }

    ipv6->saddr = intf->ip6;
    ipv6->daddr = zcfg->ip6;
    frame_len = ETH_HLEN + sizeof (struct ipv6hdr) + len;
    frame_len = max (frame_len, TTP_MIN_FRAME_LEN);
    ipv6->payload_len = htons (frame_len - ETH_HLEN - sizeof (struct ipv6hdr));

    ttp_print_ipv6_hdr (ipv6);

    return (struct ttp_tsla_shim_hdr *)(ipv6 + 1);
}


static void ttp_prepare_tth (struct ttp_tsla_type_hdr *tth, u16 len)
{
    tth->styp = 0;
    tth->vers = 0;
    tth->tthl = TTP_PROTO_TTHL;
    tth->l3gw = true; /* always set gw flag */
    tth->resv = 0;
    tth->tot_len = htons (len);
    memset (tth->pad, 0, sizeof (tth->pad));
}


static void ttp_mac_info_send_to_gws (char *mac, enum ttp_mac_opcodes opc)
{
    int zn;
    u8 *opv, *pkt;
    u16 frame_len, pkt_len;
    struct sk_buff *skb;
    struct ethhdr *eth;
    struct ttp_tsla_shim_hdr *tsh;
    struct ttp_intf_cfg *zcfg;

    if (!(opc == TTP_REMOTE_DEL || opc == TTP_REMOTE_ADD || opc == TTP_GATEWAY)) {
        return;
    }

    for (zn = 1; zn < TTP_MAX_NUM_ZONES; zn++) {
        if (zn == ttp_myzn) {
            continue;
        }
        zcfg = &ttp_zones[zn];
        if (zcfg->ver != 4 && zcfg->ver != 6) {
            continue;
        }
        if (!(skb = ttpip_skb_aloc ())) {
            TTP_LOG ("%s: Error: mac %*phC - send to zone %d failed\n",
                     __FUNCTION__, ETH_ALEN, mac, zn);
            return;
        }

        TTP_DBG ("%s: mac %*phC - send to zone %d\n", __FUNCTION__,
                 ETH_ALEN, mac, zn);

        eth = (struct ethhdr *)skb_mac_header (skb);
        pkt = (u8 *)(eth + 1);
        memcpy (eth->h_source, zcfg->dev->dev_addr, ETH_ALEN);
        memcpy (eth->h_dest, zcfg->mac, ETH_ALEN);

        /* Make canonical skb */
        skb_reset_mac_header (skb);
        skb_reset_network_header (skb);

        pkt_len = sizeof (struct ttp_tsla_shim_hdr) + 2; /* control pkt, 2B [opc, resv] */
        tsh = NULL;
        if (zcfg->ver == 4) {
            skb->protocol = eth->h_proto = htons (ETH_P_IP);
            tsh = ttp_prepare_ipv4 (pkt, pkt_len, zcfg);
            frame_len = ETH_HLEN + sizeof (struct iphdr) + pkt_len;
        }
        else if (zcfg->ver == 6) {
            skb->protocol = eth->h_proto = htons (ETH_P_IPV6);
            tsh = ttp_prepare_ipv6 (pkt, pkt_len, zcfg);
            frame_len = ETH_HLEN + sizeof (struct ipv6hdr) + pkt_len;
        }
        if (!tsh) {
            kfree_skb (skb);
            continue;
        }

        memmove (tsh->src_node, &ttpip_etype_tsla.dev->dev_addr[3], ETH_ALEN/2);
        memmove (tsh->dst_node, &mac[3], ETH_ALEN/2);
        tsh->length = 0; /* 0 => control packet; decode next 2-bytes as [opc, resv] */
        ttp_print_shim_hdr (tsh);

        opv = (u8 *)(tsh + 1);
        switch (opc) {
        case TTP_REMOTE_DEL:
            *opv = 0;
            break;
        case TTP_REMOTE_ADD:
            *opv = 1;
            break;
        case TTP_GATEWAY:
            *opv = 2;
            break;
        default:
            BUG_ON (1);         /* can't happen - if check done at beginning */
        }

        skb->dev = zcfg->dev;    /* forward to gateway */
        ttpip_pretty_print_data ("raw:", 16, true, skb->dev->name, (u8 *)eth, skb->len);
        TTP_DBG ("`<<- Tx packet: len:%d dev:%s\n", skb->len, skb->dev->name);

        skb_trim (skb, max (frame_len, TTP_MIN_FRAME_LEN));
        skb_reset_network_header (skb);
        skb_reset_mac_header (skb);
        dev_queue_xmit (skb);
    }
}


static int ttp_mactbl_add (int zn, char *mac, enum ttp_mac_opcodes opc)
{
    struct ttp_mactable *mct;

    if (!mac) {
        return -EINVAL;
    }
    if (!(zn > 0 && zn < TTP_MAX_NUM_ZONES)) {
        return -ELNRNG;
    }

    if (!(mct = ttp_mactbl_rbtree_add (mac))) {
        return -ENOMEM;
    }

    switch (opc) {
    case TTP_LOCAL:
        ttp_mac_info_send_to_gws (mac, TTP_REMOTE_ADD);
        mct->rem = 0;
        break;
    case TTP_GATEWAY:
        mct->gwf = 1;
        mct->rem = 1;
        break;
    case TTP_REMOTE_ADD:
        mct->rem = 1;
        break;
    default:
        BUG_ON (1);
        break;
    }

    mct->age = 0;
    if (mct->zon) {            /* existing entry */
        return EEXIST;
    }
    mct->zon = zn;

    return 0;
}


static void ttp_mactbl_del (int zn, char *mac)
{
    if (!mac) {
        return;
    }
    if (!(zn > 0 && zn < TTP_MAX_NUM_ZONES)) {
        return;
    }

    ttp_mactbl_rbtree_del (mac);
}

#define CLIF(ag) ((ag)<3?0:(ag)) /* to filter thrashing output around '0' age */

#define TTP_SNPRINTF_COMMON                                  \
    do {                                                     \
        TTP_SNPRINTF ("%2d  0x%02x  %*pM  %c-%c  %6d   ",    \
                      mct->zon,                              \
                      ttp_tag_index_hash_calc (mct->mac),    \
                      ETH_ALEN, mct->mac,                    \
                      mct->rem ? 'r' : 'l',                  \
                      mct->gwf ? 'g' : '-',                  \
                      CLIF (mct->age) * TTP_GW_MAC_ADV_TMR); \
    } while (0)

#define TTP_SNPRINTF_COMMON_LOCAL(cond) \
    do {                                \
        if (cond) {                     \
            continue;                   \
        }                               \
        TTP_SNPRINTF_COMMON;            \
        TTP_SNPRINTF ("<local>\n");     \
    } while (0)

#define TTP_SNPRINTF_COMMON_IPADDR(cond)             \
    do {                                             \
        if (cond) {                                  \
            continue;                                \
        }                                            \
        TTP_SNPRINTF_COMMON;                         \
        if (ttp_zones[mct->zon].ver == 4) {          \
            TTP_SNPRINTF ("%pI4\n",                  \
                          &ttp_zones[mct->zon].ip4); \
        }                                            \
        else if (ttp_zones[mct->zon].ver == 6) {     \
            TTP_SNPRINTF ("%pI6\n",                  \
                          &ttp_zones[mct->zon].ip6); \
        }                                            \
    } while (0)

static int ttp_param_mactbl_get (char *buf, const struct kernel_param *kp)
{
    int sc = 0, bs = PAGE_SIZE;
    struct ttp_mactable *mct = NULL;

    if (!ttp_mactbl_ct) {
        TTP_SNPRINTF ("<empty>\n");
        return sc;
    }

    if (!mutex_trylock (&ttp_mactable_mutx)) {
        TTP_SNPRINTF ("%s: Error: trylock failed\n", __FUNCTION__);
        return sc;
    }

    TTP_SNPRINTF (BLUE "%2s  %4s  %17s  %3s  %7s  %8s\n",
                  "zn", "hash", "--- mac-addrs ---", "rlg", "age(ms)",
                  "next-hop-gateway");

    TTP_SNPRINTF (CYAN "  Local entries:\n");
    while ((mct = ttp_mactbl_rbtree_get_next (mct))) {
        TTP_SNPRINTF_COMMON_LOCAL (!mct->val || mct->rem);
    }

    TTP_SNPRINTF (YELLOW " Remote entries:\n");
    while ((mct = ttp_mactbl_rbtree_get_next (mct))) {
        TTP_SNPRINTF_COMMON_IPADDR (!mct->val || !mct->rem || mct->gwf);
    }

    TTP_SNPRINTF (GREEN "Gateway entries:\n");
    while ((mct = ttp_mactbl_rbtree_get_next (mct))) {
        TTP_SNPRINTF_COMMON_IPADDR (!mct->val || !mct->gwf);
    }

    mutex_unlock (&ttp_mactable_mutx);

    TTP_SNPRINTF (WHITE "key: " BLUE "alive < %dms <= old < %dms(max) tot#: %d\n" CLEAR,
                  TTP_MAC_AGEOUT_OLD * TTP_GW_MAC_ADV_TMR,
                  TTP_MAC_AGEOUT_MAX * TTP_GW_MAC_ADV_TMR, ttp_mactbl_ct);
    return sc;
}

static const struct kernel_param_ops ttp_param_mactbl_ops = {
    .set = ttp_param_dummy_set, /* not settable */
    .get = ttp_param_mactbl_get,
};

module_param_cb (mactbl, &ttp_param_mactbl_ops, &ttp_mactbl_ct, 0444);
MODULE_PARM_DESC (mactbl, "   read gateway mac-address table");


static int ttp_param_shutdown_set (const char *val, const struct kernel_param *kp)
{
    int vv = 0;

    if ((0 != kstrtoint (val, 10, &vv)) || vv < 0 || vv > 2) {
        return -EINVAL;
    }

    return param_set_int (val, kp);
}

static const struct kernel_param_ops ttp_param_shutdown_ops = {
    .set = ttp_param_shutdown_set,
    .get = param_get_int,
};

module_param_cb (shutdown, &ttp_param_shutdown_ops, &ttp_shutdown, 0644);
MODULE_PARM_DESC (shutdown, " modttpoe shutdown state (read-only)");


static int ttp_param_verbose_set (const char *val, const struct kernel_param *kp)
{
    int vv = 0;

    if ((0 != kstrtoint (val, 10, &vv)) || vv < 0 || vv > 2) {
        return -EINVAL;
    }
    return param_set_int (val, kp);
}

static const struct kernel_param_ops ttp_param_verbose_ops = {
    .set = ttp_param_verbose_set,
    .get = param_get_int,
};

module_param_cb (verbose, &ttp_param_verbose_ops, &ttp_verbose, 0644);
MODULE_PARM_DESC (verbose, "  kernel log verbosity level (default=(-1), 0, 1, 2)");


static int ttp_nh4_mac_get (struct ttp_intf_cfg *zcfg)
{
    int rv = 0;
    u8 mac[ETH_ALEN];
    struct in_addr nh4;
    struct rtable *rt4;
    struct neighbour *neigh;
    struct ttp_intf_cfg *intf;

    if (IS_ERR (rt4 = ip_route_output (&init_net, zcfg->ip4.s_addr, 0, 0, 0))) {
        TTP_LOG ("%s: Error: route lookup failed: ttp-gw:%pI4\n", __FUNCTION__, &zcfg->ip4);
        rv = PTR_ERR (rt4);
        goto end;
    }
    if ((rt4->dst.dev->flags & IFF_LOOPBACK) || (!(rt4->dst.dev->flags & IFF_UP))) {
        TTP_LOG ("%s: Error: dev lookup failed: %s is %s\n", __FUNCTION__,
                 rt4->dst.dev->name, rt4->dst.dev->flags & IFF_LOOPBACK ? "LOOPBACK" : "!UP");
        rv = -EINVAL;
        goto end;
    }
    zcfg->dev = rt4->dst.dev;
    if ((intf = ttp_intf_get (zcfg, 4))) {
        zcfg->pfl = intf->pfl;
    }
    zcfg->gwy = !!rt4->rt_uses_gateway;
    nh4.s_addr = !zcfg->gwy ? zcfg->ip4.s_addr : rt4->rt_gw4;

    if (!(neigh = dst_neigh_lookup (&rt4->dst, &nh4))) {
        TTP_LOG ("%s: Error: neighbor lookup failed: nh-ip4:%pI4\n", __FUNCTION__, &nh4);
        rv = PTR_ERR (neigh);
        goto end;
    }
    memcpy (zcfg->mac, neigh->ha, ETH_ALEN);
    neigh_release (neigh);
    dst_release (&rt4->dst);
    if (is_valid_ether_addr (zcfg->mac)) {
        if (!zcfg->gwy) {
            TTP_DBG ("`->zn:%d gw: %pI4 -> mac:%*pM ->\n"
                     "      `-->via: direct -> dev:%s\n",
                     zcfg->zon, &zcfg->ip4, ETH_ALEN, zcfg->mac, zcfg->dev->name);
        }
        else {
            TTP_DBG ("`->zn:%d gw: %pI4 -> mac:%*pM ->\n"
                     "      `-->via: router:%pI4 -> dev:%s\n",
                     zcfg->zon, &zcfg->ip4, ETH_ALEN, zcfg->mac, &nh4, zcfg->dev->name);
        }
        rv = 0;  /* success */
    }
    else {
        TTP_DBG ("`->nh-mac: %pI4 unresolved, re-try arp\n", &nh4);
        eth_broadcast_addr (mac);
        arp_send (ARPOP_REQUEST, ETH_P_ARP, nh4.s_addr, zcfg->dev,
                  ttp_zones[ttp_myzn].ip4.s_addr, mac,
                  ttp_zones[ttp_myzn].dev->dev_addr, mac);
        rv = EAGAIN;
    }
end:
    return rv;
}

#define DST2RT6(dst) container_of(dst, struct rt6_info, dst)

static int ttp_nh6_mac_get (struct ttp_intf_cfg *zcfg)
{
    int rv = 0;
    struct flowi6 fl6;
    struct in6_addr nh6;
    struct rt6_info *rt6;
    struct dst_entry *dst;
    struct neighbour *neigh;
    struct ttp_intf_cfg *intf;

    memset (&fl6, 0, sizeof fl6);
    fl6.daddr = zcfg->ip6;
    if (IS_ERR (dst = ip6_route_output_flags (&init_net, NULL, &fl6, 0))) {
        TTP_LOG ("%s: Error: route6 lookup failed: gw:%pI6c\n", __FUNCTION__, &zcfg->ip6);
        rv = PTR_ERR (dst);
        goto end;
    }
    if ((dst->dev->flags & IFF_LOOPBACK) || (!(dst->dev->flags & IFF_UP))) {
        TTP_LOG ("%s: Error: dev lookup failed: %s is %s\n", __FUNCTION__,
                 dst->dev->name, dst->dev->flags & IFF_LOOPBACK ? "LOOPBACK" : "!UP");
        rv = PTR_ERR (neigh);
        goto end;
    }
    zcfg->dev = dst->dev;
    if ((intf = ttp_intf_get (zcfg, 6))) {
        zcfg->pfl = intf->pfl;
    }
    rt6 = DST2RT6 (dst);
    zcfg->gwy = !!(rt6->rt6i_flags & RTF_GATEWAY);
    nh6 = !zcfg->gwy ? zcfg->ip6 : rt6->rt6i_gateway;
    if (!(neigh = dst_neigh_lookup (&rt6->dst, &nh6))) {
        TTP_LOG ("%s: Error: neighbor lookup failed: nh-ip6:%pI6c\n", __FUNCTION__, &nh6);
        rv = PTR_ERR (neigh);
        goto end;
    }
    memcpy (zcfg->mac, neigh->ha, ETH_ALEN);
    dst_release (&rt6->dst);
    if (is_valid_ether_addr (zcfg->mac)) {
        if (!zcfg->gwy) {
            TTP_DBG ("`->zn:%d gw: %pI6c -> mac:%*pM ->\n"
                     "      `-->via: direct -> dev:%s\n",
                     zcfg->zon, &zcfg->ip6, ETH_ALEN, zcfg->mac, zcfg->dev->name);
        }
        else {
            TTP_DBG ("`->zn:%d gw: %pI6c -> mac:%*pM ->\n"
                     "      `-->via: router:%pI6c -> dev:%s\n",
                     zcfg->zon, &zcfg->ip6, ETH_ALEN, zcfg->mac, &nh6, zcfg->dev->name);
        }
        rv = 0;  /* success */
    }
    else {
        TTP_DBG ("`->nh-mac: %pI6c unresolved, re-try nd6\n", &nh6);
        neigh_resolve_output (neigh, NULL);
        rv = EAGAIN;
    }
end:
    return rv;
}


static int ttp_nhmac_get (u16 zn)
{
    int rv = 0;
    struct ttp_intf_cfg *zcfg;

    if (zn == ttp_myzn) {
        TTP_DBG ("%s: zn:%d is my_zone\n", __FUNCTION__, zn);
        goto end;
    }
    if (!(zcfg = ttp_intf_cfg_get (zn))) {
        rv = -EINVAL;
        goto end;
    }
    if (is_valid_ether_addr (zcfg->mac)) {
        TTP_DBG ("%s: zn:%d has a valid gwmac:%*phC\n", __FUNCTION__,
                 zn, ETH_ALEN, zcfg->mac);
        goto end;
    }

    if (zcfg->ver == 4) {
        rv = ttp_nh4_mac_get (zcfg);
    }
    else if (zcfg->ver == 6) {
        rv = ttp_nh6_mac_get (zcfg);
    }
    else {
        TTP_LOG ("%s: Error: zn:%d Wrong gw-ver:%d\n", __FUNCTION__, zn, zcfg->ver);
        rv = -EINVAL;
    }
end:
    return rv;
}


static int ttp_all_nhmacs_get (void)
{
    int ir, rv = 0;
    u16 zn;

    for (zn = 1; zn < TTP_MAX_NUM_ZONES; zn++) {
        if (!(ir = ttp_nhmac_get (zn))) {
            continue;
        }
        if (!rv && (EAGAIN == ir)) {
            rv = EAGAIN;
        }
    }
    return rv;
}


static void ttp_gw_local_mac_learn (struct ethhdr *eth)
{
    int rc;

    if ((rc = ttp_mactbl_add (ttp_myzn, eth->h_source, TTP_LOCAL))) {
        if (rc != EEXIST) {
            TTP_LOG ("`-> Error: mac-table full (rv:%d)\n", rc);
            return;
        }
    }
    TTP_DBG ("%s: gw_mac_adv: zn:%d  mac:%*phC%s\n", __FUNCTION__, ttp_myzn,
             ETH_ALEN, eth->h_source, rc == EEXIST ? "" : " (new)");
}


static void ttp_gw_control_handle (struct ethhdr *eth, int ver,
                                   struct iphdr *ipv4, struct ipv6hdr *ipv6,
                                   struct ttp_tsla_shim_hdr *tsh)
{
    int rc, zn;
    u8 *opv;
    struct in_addr ip4a;
    struct in6_addr ip6a;
    enum ttp_mac_opcodes opc;

    if (ver == 4) {
        ip4a.s_addr = ipv4->saddr;
        zn = ttp_gw_ipv4_get (&ip4a);
    }
    else if (ver == 6) {
        ip6a = ipv6->saddr;
        zn = ttp_gw_ipv6_get (&ip6a);
    }
    else {
        return;
    }
    if (zn <= 0) {
        TTP_LOG ("%s: Invalid zone(%d) for mac-learn: %*phC\n", __FUNCTION__,
                 zn, ETH_ALEN, eth->h_dest);
        return;
    }

    opv = (u8 *)(tsh + 1);
    if (*opv) {
        if (*opv == 1) {
            opc = TTP_REMOTE_ADD;
        }
        else if (*opv == 2) {
            opc = TTP_GATEWAY;
        }
        else {
            TTP_LOG ("%s: Invalid op(%d) mac ?Add/Del?: %*phC from zone %d\n",
                     __FUNCTION__, *opv, ETH_ALEN, eth->h_dest, zn);
            return;
        }

        TTP_DBG ("%s: Add mac: %*phC from zone %d\n", __FUNCTION__,
                 ETH_ALEN, eth->h_dest, zn);
        if ((rc = ttp_mactbl_add (zn, eth->h_dest, opc))) {
            if (rc != EEXIST) {
                TTP_LOG ("`-> Error: mac-table full (rv:%d)\n", rc);
            }
        }
    }
    else { /* *opv == 0 */
        TTP_DBG ("%s: Del mac: %*phC from zone %d\n", __FUNCTION__,
                 ETH_ALEN, eth->h_dest, zn);
        ttp_mactbl_del (zn, eth->h_dest);
    }
}


static int ttpip_frm_recv (struct sk_buff *skb, struct net_device *dev,
                           struct packet_type *ptype, struct net_device *odev)
{
    int zs = 0, zt = 0;
    u16 frame_len, pkt_len;
    struct ttp_tsla_type_hdr *tth;
    struct ttp_tsla_shim_hdr *tsh;
    struct ttp_intf_cfg *zcfg;
    struct ethhdr *eth, neth = {0};
    struct ttp_mactable *mtbl;

    if (ttp_shutdown) {
        TTP_LOG ("%s: <<- Tx frame dropped: ttp-gw is shutdown\n", __FUNCTION__);
        goto end;
    }

    eth = (struct ethhdr *)skb_mac_header (skb);
    if (!ether_addr_equal (ttpip_etype_tsla.dev->dev_addr, eth->h_dest)) {
        goto end;
    }
    if (skb_headroom (skb) < TTP_IP_HEADROOM) {
        if (pskb_expand_head (skb, TTP_IP_HEADROOM, 0, GFP_ATOMIC)) {
            TTP_LOG ("%s: Drop frame: insufficient headroom\n", __FUNCTION__);
            goto end;
        }
    }

    TTP_DBG ("%s: ->> Rx frame: len:%d dev:%s\n", __FUNCTION__, skb->len, skb->dev->name);
    ttpip_pretty_print_data ("raw:", 16, false, skb->dev->name, (u8 *)eth, skb->len);

    tth = (struct ttp_tsla_type_hdr *)(eth + 1);
    ttp_print_tsla_type_hdr (tth);

    if (tth->tthl != TTP_PROTO_TTHL) {
        TTP_LOG ("%s: Drop frame: Incorrect TTHL: (%d)\n", __FUNCTION__, tth->tthl);
        goto end;
    }
    if (!tth->l3gw) {
        TTP_LOG ("%s: Drop frame: Improper ingress gw frame: 'l3gw' flag not set\n",
                 __FUNCTION__);
        goto end;
    }

    tsh = (struct ttp_tsla_shim_hdr *)(tth + 1);
    ttp_print_shim_hdr (tsh);

    /* Decode shim src/dst_node fields */
    ttp_mac_from_shim (neth.h_dest, tsh->dst_node);
    ttp_mac_from_shim (neth.h_source, tsh->src_node);

    /* Shim dest-mac == my-mac => gw-mac-adv node-reply; local-mac learn */
    if (ether_addr_equal (neth.h_dest, ttpip_etype_tsla.dev->dev_addr)) {
        ttp_gw_local_mac_learn (&neth);
        goto end; /* consume frame */
    }

    /* Lookup src-mac addr in mactbl */
    if ((mtbl = ttp_mactbl_find (neth.h_source))) {
        TTP_DBG ("%s: found src-mac:%*phC src-zone:%d\n", __FUNCTION__,
                 ETH_ALEN, mtbl->mac, mtbl->zon);
        if (!(zs = mtbl->zon)) {
            TTP_LOG ("%s: Drop frame: Invalid src-zone\n", __FUNCTION__);
            goto end;
        }
    }
    else {
        TTP_DBG ("%s: Error: Not found src-mac:%*phC in mactbl\n", __FUNCTION__,
                 ETH_ALEN, neth.h_source);
        goto end;
    }
    /* Lookup dst-mac addr in mactbl */
    if ((mtbl = ttp_mactbl_find (neth.h_dest))) {
        TTP_DBG ("%s: found dst-mac:%*phC tgt-zone:%d\n", __FUNCTION__,
                 ETH_ALEN, mtbl->mac, mtbl->zon);
        if (!(zt = mtbl->zon)) {
            TTP_LOG ("%s: Drop frame: Invalid tgt-zone\n", __FUNCTION__);
            goto end;
        }
    }
    else {
        TTP_DBG ("%s: Error: Not found dst-mac:%*phC in mactbl\n", __FUNCTION__,
                 ETH_ALEN, neth.h_dest);
        goto end;
    }
    if (zs == zt) {
        TTP_LOG ("%s: Drop frame: src-zone == dst-zone(%d)\n", __FUNCTION__, zs);
        goto end;
    }
    if (!(zcfg = ttp_intf_cfg_get (zt))) {
        TTP_LOG ("%s: Drop frame: error getting zone config from tgt-zone(%d)\n",
                 __FUNCTION__, zt);
        goto end;
    }
    if (!is_valid_ether_addr (zcfg->mac)) {
        TTP_LOG ("`->Invalid gw-mac:%*pM, Drop frame: len:%d dev:%s\n",
                 ETH_ALEN, zcfg->mac, skb->len, skb->dev->name);
        ttp_nhmac_get (zt); /* trigger arp, no timers are kicked off */
        goto end;
    }

    TTP_DBG ("->> Ingress gw: ttp->ipv%d zn:%d->%d len:%d dev:%s\n",
             zcfg->ver, zs, zt, skb->len, skb->dev->name);

    /* Make canonical skb */
    skb_reset_mac_header (skb);
    skb_reset_network_header (skb);

    skb_pull (skb, (tth->tthl * 4)); /* strip tesla-type header */

    pkt_len = ntohs (tsh->length); /* incoming len in shim header */
    tsh = NULL;
    if (zcfg->ver == 4) {
        skb_push (skb, sizeof (struct iphdr)); /* add IPv4 header */
        skb->protocol = htons (ETH_P_IP);
        tsh = ttp_prepare_ipv4 (skb->data, pkt_len, zcfg);
        frame_len = ETH_HLEN + sizeof (struct iphdr) + pkt_len;
    }
    else if (zcfg->ver == 6) {
        skb_push (skb, sizeof (struct ipv6hdr)); /* add IPv6 header */
        skb->protocol = htons (ETH_P_IPV6);
        tsh = ttp_prepare_ipv6 (skb->data, pkt_len, zcfg);
        frame_len = ETH_HLEN + sizeof (struct ipv6hdr) + pkt_len;
    }
    if (!tsh) {
        goto end;
    }

    skb_push (skb, ETH_HLEN); /* add ethernet header */
    eth = (struct ethhdr *)skb->data;
    memcpy (eth->h_source, zcfg->dev->dev_addr, ETH_ALEN);
    memcpy (eth->h_dest, zcfg->mac, ETH_ALEN);
    eth->h_proto = skb->protocol;

    ttpip_pretty_print_data ("raw:", 16, true, skb->dev->name, (u8 *)eth, skb->len);
    TTP_DBG ("`<<- Tx packet: len:%d dev:%s\n", skb->len, skb->dev->name);

    skb->dev = zcfg->dev;    /* forward to gateway */
    skb_trim (skb, max (frame_len, TTP_MIN_FRAME_LEN));
    skb_reset_network_header (skb);
    skb_reset_mac_header (skb);
    dev_queue_xmit (skb);
    return 0;

end:
    kfree_skb (skb);
    return 0;
}


static int ttpip_pkt_recv (struct sk_buff *skb, struct net_device *dev,
                           struct packet_type *ptype, struct net_device *odev)
{
    int tot_len, zs, zt, ver;
    struct iphdr *ipv4;
    struct ipv6hdr *ipv6;
    struct ttp_tsla_type_hdr *tth;
    struct ttp_tsla_shim_hdr *tsh;
    struct ethhdr *eth, neth = {0};
    struct ttp_mactable *mtbl;

    if (ttp_shutdown) {
        TTP_LOG ("%s: ->> Rx pkt dropped: ttp-gw is shutdown\n", __FUNCTION__);
        goto end;
    }

    eth = (struct ethhdr *)skb_mac_header (skb);
    if (eth->h_proto == htons (ETH_P_IP)) {
        ver = 4;
        ipv4 = (struct iphdr *)skb_network_header (skb); /* skb_network_header */
        if (ttp_zones[ttp_myzn].ip4.s_addr != ipv4->daddr ||
            IPPROTO_TTP != ipv4->protocol) {
            goto end;
        }
    }
    else if (eth->h_proto == htons (ETH_P_IPV6)) {
        ver = 6;
        ipv6 = (struct ipv6hdr *)skb_network_header (skb);
        if (ipv6_addr_cmp (&ipv6->daddr, &ttp_zones[ttp_myzn].ip6) ||
            ipv6->nexthdr != IPPROTO_TTP) {
            goto end;
        }
    }
    else {
        TTP_LOG ("`->Error: Unknown IP version for gw - pkt dropped\n");
        goto end;
    }
    if (skb_headroom (skb) < TTP_IP_HEADROOM) {
        if (pskb_expand_head (skb, TTP_IP_HEADROOM, 0, GFP_ATOMIC)) {
            TTP_LOG ("%s: Drop pkt: insufficient headroom\n", __FUNCTION__);
            goto end;
        }
    }

    TTP_DBG ("%s: ->> Rx pkt: len:%d dev:%s\n", __FUNCTION__, skb->len, skb->dev->name);
    ttpip_pretty_print_data ("raw:", 16, false, skb->dev->name, (u8 *)eth, skb->len);

    /* Make canonical skb */
    skb_reset_mac_header (skb);
    skb_reset_network_header (skb);

    /* Decap IP to extract tsh - handle ipv4 or ipv6 */
    if (ver == 4) {
        ttp_print_ipv4_hdr (ipv4);
        tsh = (struct ttp_tsla_shim_hdr *)(ipv4 + 1);
        tot_len = ntohs (ipv4->tot_len);

        skb_pull (skb, (ipv4->ihl * 4)); /* strip IPv4 header */
    }
    else if (ver == 6) {
        ttp_print_ipv6_hdr (ipv6);
        tsh = (struct ttp_tsla_shim_hdr *)(ipv6 + 1);
        tot_len = ntohs (ipv6->payload_len) + sizeof (struct ipv6hdr);

        skb_pull (skb, sizeof (struct ipv6hdr)); /* strip IPv6 header */
    }
    else {
        goto end;
    }

    /* Decode shim src/dst_node fields */
    ttp_mac_from_shim (neth.h_dest, tsh->dst_node);
    ttp_mac_from_shim (neth.h_source, tsh->src_node);

    /* tsh length == 0 => mac learning packet */
    if (tsh->length == 0) {
        ttp_gw_control_handle (&neth, ver, ipv4, ipv6, tsh);
        goto end; /* consume packet */
    }

    skb_push (skb, sizeof (struct ttp_tsla_type_hdr)); /* add tesla-type header */

    tth = (struct ttp_tsla_type_hdr *)skb->data;
    ttp_prepare_tth (tth, skb->len);

    ttp_print_eth_hdr (eth);
    ttp_print_shim_hdr (tsh);
    ttp_print_tsla_type_hdr (tth);

    /* Prepare TTPoE frame to forward to destination ttp-node */
    skb_push (skb, ETH_HLEN); /* add ethernet header */
    eth = (struct ethhdr *)skb->data;
    memcpy (eth->h_source, ttpip_etype_tsla.dev->dev_addr, ETH_ALEN);
    memcpy (eth->h_dest, neth.h_dest, ETH_ALEN);
    eth->h_proto = htons (TESLA_ETH_P_TTPOE);

    skb_trim (skb, max ((u16)(ETH_HLEN + tot_len), TTP_MIN_FRAME_LEN));
    skb->len = max ((u16)skb->len, TTP_MIN_FRAME_LEN);

    /* Lookup src-mac addr in mactbl */
    if ((mtbl = ttp_mactbl_find (neth.h_source))) {
        TTP_DBG ("%s: found src-mac:%*phC zn:%d\n", __FUNCTION__,
                 ETH_ALEN, mtbl->mac, mtbl->zon);
        zs = mtbl->zon;
    }
    /* Lookup dst-mac addr in mactbl */
    if ((mtbl = ttp_mactbl_find (neth.h_dest))) {
        TTP_DBG ("%s: found dst-mac:%*phC zn:%d\n", __FUNCTION__,
                 ETH_ALEN, mtbl->mac, mtbl->zon);
        zt = mtbl->zon;
    }

    if (!zs || !zt) {
        TTP_LOG ("%s: Drop frame: Invalid src-node (%d) and/or dst-node (%d)\n",
                 __FUNCTION__, zs, zt);
        goto end;
    }
    if (zs == zt) {
        TTP_LOG ("%s: Drop pkt: src-node and dst-node are in same zone (%d)\n",
                 __FUNCTION__,
                 zs);
        goto end;
    }

    TTP_DBG ("<<-- Egress gw: ttp<-ipv%d zn:%d<-%d len:%d dev:%s\n",
             ver, zt, zs, skb->len, skb->dev->name);

    skb->dev = ttpip_etype_tsla.dev; /* forward frame to ttp-nodes within zone */
    ttpip_pretty_print_data ("raw:", 16, true, skb->dev->name, (u8 *)eth, skb->len);
    TTP_DBG ("<<- Tx frame: len:%d dev:%s\n", skb->len, skb->dev->name);

    skb_reset_network_header (skb);
    skb_reset_mac_header (skb);
    dev_queue_xmit (skb);
    return 0;

end:
    kfree_skb (skb);
    return 0;
}


static void ttp_nh_mac_timer_cb (struct timer_list *tl)
{
    static int tries = 0;
    const int max_tries = 5;
    int rv, to = 200;

    if (tries == max_tries) {
        ttp_shutdown = 1;
        TTP_LOG ("Error: route/arp lookup failed (%d retries)"
                 " - ttpip-gw has shutdown\n", max_tries);
    }
    else if ((rv = ttp_all_nhmacs_get ()) < 0) {
        TTP_LOG ("Error: route/neighbor lookup failed\n");
        del_timer (&ttp_nh_mac_timer_head);
    }
    else if (0 == rv) {
        TTP_DBG ("%s: resolved all nh-macs\n", __FUNCTION__);
        del_timer (&ttp_nh_mac_timer_head);
    }
    else if (EAGAIN == rv) {
        to *= (!tries++ ? 1 : 4); /* 2nd, 3rd,.. retry delayed 4x */
        mod_timer (&ttp_nh_mac_timer_head, jiffies + to);
        TTP_DBG ("%s: re-try(#%d): nh-macs\n", __FUNCTION__, tries);
    }
}


static void ttp_gw_mac_adv_timer_cb (struct timer_list *tl)
{
    struct sk_buff *skb;
    struct ethhdr *eth;
    struct ttp_tsla_type_hdr *tth;
    struct ttp_tsla_shim_hdr *tsh;
    struct ttp_mactable *mct = NULL;
    u8 *opv;

    if (ttp_shutdown) {
        TTP_LOG ("%s: skipping: ttp-gw is shutdown\n", __FUNCTION__);
        goto end;
    }

    if (!(skb = ttpip_skb_aloc ())) {
        TTP_LOG ("%s: out of memory\n", __FUNCTION__);
        goto end;
    }

    /* Construct l2-mcast frame to adv my gw-mac to nodes within my zone */
    eth = (struct ethhdr *)skb_mac_header (skb);
    memcpy (eth->h_source, ttpip_etype_tsla.dev->dev_addr, ETH_ALEN);
    memcpy (eth->h_dest, ttpip_etype_tsla.dev->dev_addr, ETH_ALEN);
    eth->h_dest[0] |= 0x3; /* convert to multicast link-local mac address */
    eth->h_proto = htons (TESLA_ETH_P_TTPOE);

    tth = (struct ttp_tsla_type_hdr *)(eth + 1);
    ttp_prepare_tth (tth, 0);

    tsh = (struct ttp_tsla_shim_hdr *)(tth + 1);
    memmove (tsh->src_node, &ttpip_etype_tsla.dev->dev_addr[3], ETH_ALEN/2);
    memmove (tsh->dst_node, eth->h_dest, ETH_ALEN/2);
    tsh->length = htons (26);

    opv = (u8 *)(tsh + 1);
    *opv = 2; /* OPEN_NACK */

    skb->dev = ttpip_etype_tsla.dev; /* forward frame to ttp-nodes within zone */
    ttpip_pretty_print_data ("raw:", 16, true, skb->dev->name, (u8 *)eth, skb->len);
    TTP_DBG ("<<- Tx packet: gw-mac-adv frame: len:%d dev:%s\n", skb->len, skb->dev->name);

    skb_reset_network_header (skb);
    skb_reset_mac_header (skb);
    dev_queue_xmit (skb);

    /* Walk mactbl, send node-macs learned / aged in my zone to remote gws */
    while ((mct = ttp_mactbl_rbtree_get_next (mct))) {
        if (!mct->val || (mct->rem && !mct->gwf)) {
            continue;
        }
        if (mct->age >= TTP_MAC_AGEOUT_OLD) {
            if (!mct->rem) {
                /* reached OLD threshold - withdraw local MAC */
                ttp_mac_info_send_to_gws (mct->mac, TTP_REMOTE_DEL);
            }

            if (mct->age >= TTP_MAC_AGEOUT_MAX) {
                /* reached Max threshold - remove this entry */
                ttp_mactbl_del (mct->zon, mct->mac);
                mct = NULL;     /* force restart loop */
                continue;
            }
        }
        mct->age++;
    }

    /* Finally send my gw-mac to remote gws */
    ttp_mac_info_send_to_gws ((char *)ttpip_etype_tsla.dev->dev_addr, TTP_GATEWAY);

end:
    ttp_gw_mac_adv_timer_head.expires = jiffies + msecs_to_jiffies (TTP_GW_MAC_ADV_TMR);
    add_timer (&ttp_gw_mac_adv_timer_head);
}


static int __init ttpip_init (void)
{
    u16 zn;
    int rv, dv, in;
    struct list_head *lhp;
    struct net_device *dev;
    struct in_ifaddr *ifa4;
    struct inet6_ifaddr *ifa6;
    struct ttp_intf_cfg *zcfg, *edev, *intf;

#if (TTP_TTH_MATCHES_IPH == 1)
    if (sizeof (struct ttp_tsla_type_hdr) != sizeof (struct iphdr)) {
        TTP_LOG ("Error: tth size != iph size - unloading\n");
        rv = -EINVAL;
        goto error;
    }
#endif

    if (!ttp_num_gwips) {
        TTP_LOG ("Error: no gwips specified - unloading\n");
        rv = -ENODEV;
        goto error;
    }
    if (!ttp_dev || (!(ttpip_etype_tsla.dev = dev_get_by_name (&init_net, ttp_dev)))) {
        TTP_LOG ("Error: Could not get dev (%s) - unloading\n", ttp_dev ?: "<unspecified>");
        rv = -ENODEV;
        goto error;
    }
    dev_put (ttpip_etype_tsla.dev);
    if (!(ttpip_etype_tsla.dev->flags & IFF_UP)) {
        TTP_LOG ("Error: Device dev (%s) is DOWN - unloading\n", ttp_dev);
        rv = -ENETDOWN;
        goto error;
    }
    read_lock (&dev_base_lock);
    rv = 0;
    for (dev = first_net_device (&init_net); dev; dev = next_net_device (dev)) {
        if (ttp_num_edevs >= (TTP_MAX_NUM_EDEVS - 1)) {
            TTP_LOG ("Error: Exceeded size of interface list: %d/%d\n",
                     ttp_num_edevs, TTP_MAX_NUM_EDEVS);
            return -ENOSPC;
        }
        if (dev->flags & IFF_LOOPBACK) {
            continue;
        }
        if (!(dev->flags & IFF_UP)) {
            continue;
        }
        ttp_edevs[ttp_num_edevs++].dev = dev;
    }
    for (dv = 0, in = 0; dv < ttp_num_edevs; dv++) {
        edev = &ttp_edevs[dv];
        dev = edev->dev;
        rcu_read_lock ();

        /* Look for ipv4 address */
        for (ifa4 = rcu_dereference (dev->ip_ptr->ifa_list);
             ifa4; ifa4 = rcu_dereference(ifa4->ifa_next)) {

            intf = &ttp_intfs[ttp_num_intfs++];
            intf->dev = dev;
            intf->ver = 4;
            intf->ip4.s_addr = ifa4->ifa_address;
            intf->pfl = ifa4->ifa_prefixlen;

            TTP_DBG ("`->%s #%d ip4:%pI4/%d%s\n", dev->name, ttp_num_intfs,
                     &ifa4->ifa_address, ifa4->ifa_prefixlen,
                     !strncmp (dev->name, ttp_dev, 8) ? " (ttp-dev)" : "");

            if (!strncmp (dev->name, ttp_dev, 8)) {
                TTP_LOG ("`->Warning: ttp-dev:%s has IPv4 address\n", dev->name);
                continue;
            }
            for (zn = 1; zn < TTP_MAX_NUM_ZONES; zn++) {
                zcfg = &ttp_zones[zn]; /* pick array entry (cannot use ttp_intf_cfg_get()) */
                if (zcfg->ip4.s_addr == ifa4->ifa_address) {
                    if (ttp_myzn) {
                        TTP_LOG ("Error: zn:%d repeated zone (my_zone:%d)\n",
                                 zn, ttp_myzn);
                        rv = -EEXIST;
                        break;
                    }
                    if (zcfg->dev) {
                        TTP_LOG ("Error: zn:%d repeated ipv4 device: (dev:%s)\n",
                                 zn, dev->name);
                        rv = -EEXIST;
                        break;
                    }
                    intf->zon = zn;
                    ttp_myzn = zn;
                    zcfg->zon = zn;
                    ttpip_etype_lyr3.dev = zcfg->dev = dev;
                    ttpip_etype_lyr3.type = htons (ETH_P_IP);
                    memcpy (zcfg->mac, zcfg->dev->dev_addr, ETH_ALEN);
                    zcfg->pfl = ifa4->ifa_prefixlen;
                    TTP_DBG ("`->zone found: zn:%d dev:%s ip4:%pI4/%d\n",
                             ttp_myzn, dev->name, &zcfg->ip4, zcfg->pfl);
                }
            }
        }
        rcu_read_unlock();
        ifa6 = NULL;

        /* Look for ipv6 address */
        list_for_each (lhp, &dev->ip6_ptr->addr_list) {
            if (!(ifa6 = list_entry (lhp, struct inet6_ifaddr, if_list))) {
                break;
            }
            intf = &ttp_intfs[ttp_num_intfs++];
            intf->dev = dev;
            intf->ver = 6;
            intf->ip6 = ifa6->addr;
            intf->pfl = ifa6->prefix_len;
            TTP_DBG ("`->%s #%d ip6:%pI6c/%d%s\n", dev->name, ttp_num_intfs,
                     &ifa6->addr, ifa6->prefix_len,
                     !strncmp (dev->name, ttp_dev, 8) ? " (ttp-dev)" : "");
            if (!strncmp (dev->name, ttp_dev, 8)) {
                if (!(ipv6_addr_type (&ifa6->addr) & IPV6_ADDR_LINKLOCAL)) {
                    TTP_LOG ("`->Warning: ttp-dev:%s has IPv6 address\n", dev->name);
                }
                continue;
            }
            for (zn = 1; zn < TTP_MAX_NUM_ZONES; zn++) {
                zcfg = &ttp_zones[zn]; /* pick array entry (cannot use ttp_intf_cfg_get()) */
                if (zcfg->ver == 6 && 0 == ipv6_addr_cmp (&zcfg->ip6, &ifa6->addr)) {
                    if (ttp_myzn) {
                        TTP_LOG ("Error: zn:%d repeated zone (my_zone:%d)\n",
                                 zn, ttp_myzn);
                        rv = -EINVAL;
                        break;
                    }
                    if (zcfg->dev) {
                        TTP_LOG ("Error: zn:%d repeated ipv6 device: (dev:%s)\n",
                                 zn, dev->name);
                        rv = -EEXIST;
                        break;
                    }
                    intf->zon = zn;
                    ttp_myzn = zn;
                    zcfg->zon = zn;
                    ttpip_etype_lyr3.dev = zcfg->dev = dev;
                    ttpip_etype_lyr3.type = htons (ETH_P_IPV6);
                    memcpy (zcfg->mac, zcfg->dev->dev_addr, ETH_ALEN);
                    zcfg->pfl = ifa6->prefix_len;
                    TTP_DBG ("`->zone found: zn:%d dev:%s ip6:%pI6c/%d\n",
                             ttp_myzn, dev->name, &zcfg->ip6, zcfg->pfl);
                }
            }
        }
        if (!ifa4 && !ifa6) {
            TTP_DBG ("`->none%s\n", !strncmp(dev->name, ttp_dev, 8)?" (ttp-dev)":"");
        }
    }
    read_unlock (&dev_base_lock);

    if (rv < 0) {
        goto error;
    }
    if (!ttp_myzn) {
        TTP_LOG ("Error: zone: not known - unloading\n");
        rv = -EINVAL;
        goto error;
    }
    if (!(zcfg = ttp_intf_cfg_get (ttp_myzn))) {
        TTP_LOG ("Error: No zone-config for my-zone(%d) - unloading\n", ttp_myzn);
        rv = -ENODEV;
        goto error;
    }
    if (!zcfg->dev) {
        TTP_LOG ("Error: No layer3 interface for my-zone - unloading\n");
        rv = -ENODEV;
        goto error;
    }
    if ((rv = ttp_all_nhmacs_get ()) < 0) {
        TTP_LOG ("Error: resolve_nh_mac failed - unloading\n");
        goto error;
    }
    if (rv) {              /* to rv == EAGAIN from all_nhmacs_get */
        timer_setup (&ttp_nh_mac_timer_head, &ttp_nh_mac_timer_cb, 0);
        ttp_nh_mac_timer_head.expires = jiffies + 200;
        add_timer (&ttp_nh_mac_timer_head);
        TTP_DBG ("%s: re-try: nh-macs\n", __FUNCTION__);
    }
    TTP_DBG ("%s: ip%d-if:'%s' mac:%*pM\n"
             "            ttp-if:'%s' mac:%*pM\n", __FUNCTION__, zcfg->ver,
             zcfg->dev->name, ETH_ALEN, zcfg->dev->dev_addr,
             ttpip_etype_tsla.dev->name, ETH_ALEN, ttpip_etype_tsla.dev->dev_addr);

    timer_setup (&ttp_gw_mac_adv_timer_head, &ttp_gw_mac_adv_timer_cb, 0);
    ttp_gw_mac_adv_timer_head.expires = jiffies + 10; /* start soon */
    add_timer (&ttp_gw_mac_adv_timer_head);

    mutex_init (&ttp_mactable_mutx);

    dev_add_pack (&ttpip_etype_tsla);
    dev_add_pack (&ttpip_etype_lyr3);
    TTP_DBG ("------------------ Module modttpip.ko loaded -----------------+\n");
    ttp_shutdown = 0;           /* enable for business */
    return 0;
error:
    TTP_DBG ("~~~~~~~~~~~~~~~~ Module modttpip.ko not loaded ~~~~~~~~~~~~~~~+\n");
    return rv;
}


static void __exit ttpip_exit (void)
{
    del_timer (&ttp_gw_mac_adv_timer_head);
    del_timer (&ttp_nh_mac_timer_head);
    dev_remove_pack (&ttpip_etype_tsla);
    dev_remove_pack (&ttpip_etype_lyr3);
    TTP_DBG ("~~~~~~~~~~~~~~~~~ Module modttpip.ko unloaded ~~~~~~~~~~~~~~~~+\n");
}


module_init (ttpip_init);
module_exit (ttpip_exit);

MODULE_AUTHOR ("dntundlam@tesla.com");
MODULE_DESCRIPTION ("TTP IP Gateway");
MODULE_VERSION ("1.0");
MODULE_LICENSE ("GPL");
