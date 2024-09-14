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


#define TTP_MAC_TABLE_SIZE  256
#define TTP_MAC_AGEOUT_MAX   60

static struct ttp_mac_table {
    u8 mac[ETH_ALEN];
    u8 zon;
    u8 age;
} ttp_mac_addrs[TTP_MAC_TABLE_SIZE];

u8  ttp_mactbl_ct;
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


static inline void ttp_print_ipv4_hdr (struct iphdr *ip)
{
    TTP_DBG ("ip4h: %*ph\n", 10, ip);
    TTP_DBG ("      %*ph\n", (int)sizeof (*ip) - 10, (10 + (u8 *)ip));
    TTP_DBG ("  ver:%d ihl:%d ttl:%d tos:%02x len:%d proto:%d%s\n",
             ip->version, ip->ihl, ip->ttl, ip->tos, ntohs (ip->tot_len),
             ip->protocol, ip->protocol == IPPROTO_TTP ? " (TTP)" : "");
    TTP_DBG (" dip4:%pI4 sip4:%pI4\n", &ip->daddr, &ip->saddr);
}


static inline void ttp_print_ipv6_hdr (struct ipv6hdr *ipv6)
{
    TTP_DBG ("ip6h: %*ph\n", 20, ipv6);
    TTP_DBG ("      %*ph\n", (int)sizeof (*ipv6) - 20, (20 + (u8 *)ipv6));
    TTP_DBG ("  ver:%d len:%d ttl:%d proto:%d%s\n",
             ipv6->version, ntohs (ipv6->payload_len), ipv6->hop_limit,
             ipv6->nexthdr, ipv6->nexthdr == IPPROTO_TTP ? " (TTP)" : "");
    TTP_DBG (" dip6:%pI6c sip6:%pI6c\n", &ipv6->daddr, &ipv6->saddr);
}


static inline struct ttp_intf_cfg *ttp_intf_cfg_get (int zn)
{
    struct ttp_intf_cfg *zcfg;

    if (zn < TTP_MAX_NUM_ZONES) {
        zcfg = &ttp_zones[zn];
        if (zcfg->ver) {
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
    int zn, sc = 0, bs = 700;
    struct ttp_intf_cfg *zcfg;
    char ipaddr_str[64], *via;

    BUG_ON (!ttp_num_gwips);
    int n = snprintf (buf + sc, bs - sc, BLUE "%2s %29s  %-17s  %-8s %s\n" CLEAR,
                    "zn", "ttp-layer3-gateway-ip", "next-hop-mac-addr", "device", "via");
    if (n < 0 || n >= bs - sc) {
        return sc;
    }
    sc += n;
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
        n = snprintf (buf + sc, bs - sc,
                        "%s%d%c %26s/%-2d  %*pM  %-8s %s\n" CLEAR,
                        zn == ttp_myzn ? GREEN : NOCOLOR,
                        zn, zn == ttp_myzn ? '*' : ' ', ipaddr_str, zcfg->pfl,
                        ETH_ALEN, zcfg->mac, zcfg->dev->name,
                        zn == ttp_myzn ? "*zn" : via);
        if (n < 0 || n >= bs - sc) {
            return sc;
        }
        sc += n;
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
    int iv, sc = 0, bs = 1000;
    struct ttp_intf_cfg *dev;
    char ipaddr_str[64], zc, st;

    int n = snprintf (buf + sc, bs - sc, BLUE "%2s %2s  %-8s %29s  %17s\n" CLEAR,
                    "zn", "if", "device", "interface-ip-address", "device-mac-addr");
    if (n < 0 || n >= bs - sc) {
        return sc;
    }
    sc += n;
    for (iv = 0; iv < ttp_num_intfs; iv++) {
        dev = &ttp_intfs[iv];
        zc = st = ' ';
        if (!dev->dev) {
            n = snprintf (buf + sc, bs - sc, GRAY "%c%c %2d  %-8s\n" CLEAR,
                            zc, st, iv + 1, "none");
            if (n < 0 || n >= bs - sc) {
                return sc;
            }
            sc += n;
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
        n = snprintf (buf + sc, bs - sc, "%s%c%c %2d  %-8s %26s/%-2d  %*pM\n" CLEAR,
                        dev->zon == ttp_myzn ? GREEN : NOCOLOR,
                        zc, st, iv, dev->dev->name,
                        ipaddr_str, dev->pfl, ETH_ALEN, dev->dev->dev_addr);
        if (n < 0 || n >= bs - sc) {
            return sc;
        }
        sc += n;
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
    int iv, sc = 0, bs = 700;
    struct ttp_intf_cfg *dev;

    int n = snprintf (buf + sc, bs - sc, BLUE "%2s  %-8s %17s\n" CLEAR,
                    "if", "device", "device-mac-addr");
    if (n < 0 || n >= bs - sc) {
        return sc;
    }
    sc += n;
    for (iv = 0; iv < ttp_num_edevs; iv++) {
        dev = &ttp_edevs[iv];
        if (!dev->dev) {
            n = snprintf (buf + sc, bs - sc, "%2d %-8s\n", iv, "none");
            if (n < 0 || n >= bs - sc) {
                return sc;
            }
            sc += n;
            continue;
        }
        n = snprintf (buf + sc, bs - sc, "%s%-2d  %-8s %*pM\n" CLEAR,
                        !strncmp (dev->dev->name, ttp_dev, 8) ? RED : NOCOLOR,
                        iv, dev->dev->name, ETH_ALEN, dev->dev->dev_addr);
        if (n < 0 || n >= bs - sc) {
            return sc;
        }
        sc += n;
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


static struct ttp_mac_table *ttp_param_mactbl_find (char *mac)
{
    int iv;

    if (!mac) {
        return NULL;
    }
    for (iv = 0; iv < TTP_MAC_TABLE_SIZE; iv++) {
        if (ether_addr_equal (ttp_mac_addrs[iv].mac, mac)) {
            return &ttp_mac_addrs[iv];
        }
    }
    return NULL;
}


static int ttp_param_mactbl_add (int zn, char *mac, int *ix)
{
    int iv;

    if (!mac) {
        return -EINVAL;
    }
    if (!(zn > 0 && zn < TTP_MAX_NUM_ZONES)) {
        return -ELNRNG;
    }
    for (iv = 0; iv < TTP_MAC_TABLE_SIZE; iv++) {
        if (ether_addr_equal (ttp_mac_addrs[iv].mac, mac)) {
            ttp_mac_addrs[iv].age = 0;
            ttp_mac_addrs[iv].zon = zn;
            if (ix) {
                *ix = iv;
            }
            return EEXIST;
        }
        if (is_zero_ether_addr (ttp_mac_addrs[iv].mac)) {
            ether_addr_copy (ttp_mac_addrs[iv].mac, mac);
            ttp_mac_addrs[iv].zon = zn;
            ttp_mactbl_ct++;
            if (ix) {
                *ix = iv;
            }
            return 0;
        }
    }
    return -ENOMEM;
}


static int ttp_param_mactbl_set (const char *val, const struct kernel_param *kp)
{
    int len, rc, iv;
    u8 mac[ETH_ALEN], zn;
    const u8 *lvl;

    len = strcspn (val, ",");
    if (len) {
        lvl = val;
        for (iv = 0; iv < ETH_ALEN; iv++) {
            mac[iv] = simple_strtol (lvl, NULL, 16) & 0xff;
            lvl += 2;
            if (iv < (ETH_ALEN - 1) && (*lvl != ':')) {
                return -EDESTADDRREQ;
            }
            if ((iv == (ETH_ALEN - 1) &&
                 (*lvl != ',' && *lvl != '\n' && *lvl != '\0'))) {
                return -EDESTADDRREQ;
            }
            lvl++;
        }
        if (!is_valid_ether_addr (mac)) {
            return -EDESTADDRREQ;
        }
    }

    lvl = val + len;
    if (*lvl != ',') {
        return -ENOKEY;
    }

    lvl++;
    zn = simple_strtol (lvl, NULL, 10);
    if (!(zn > 0 && zn < TTP_MAX_NUM_ZONES)) {
        return -ELNRNG;
    }
    if (zn == ttp_myzn) {
        return -EKEYREJECTED;
    }
    TTP_DBG ("%s: zn:%d mac:%*phC\n", __FUNCTION__, zn, ETH_ALEN, mac);

    iv = 0;
    if ((rc = ttp_param_mactbl_add (zn, mac, &iv))) {
        if (rc != EEXIST) {
            TTP_LOG ("`-> Error: mac-table full (rv:%d)\n", rc);
            return -ENOSPC;
        }
    }
    TTP_DBG ("%s: zn:%d  mac:%*phC%s\n", __FUNCTION__,
             ttp_myzn, ETH_ALEN, mac, rc == EEXIST ? "" : " (new)");
    return 0;
}


static int ttp_param_mactbl_get (char *buf, const struct kernel_param *kp)
{
    int sc = 0, bs = 1000, iv;
    int n = 0;
    
    if (!ttp_mactbl_ct) {
        n = snprintf (buf + sc, bs - sc, "<empty>\n");
        if (n < 0 || n >= bs - sc) {
            return sc;
        }
        sc += n;
        return sc;
    }

    n = snprintf (buf + sc, bs - sc, "zn  hash  --- mac-addrs ---  age\n");
    if (n < 0 || n >= bs - sc) {
        return sc;
    }
    sc += n;

    for (iv = 0; iv < ttp_mactbl_ct; iv++) {
        if (!is_zero_ether_addr (ttp_mac_addrs[iv].mac)) {
            n = snprintf (buf + sc, bs - sc, "%2d  %4d  %*pM  %3d%s\n",
                            ttp_mac_addrs[iv].zon,
                            ttp_tag_index_hash_calc (ttp_mac_addrs[iv].mac),
                            ETH_ALEN, ttp_mac_addrs[iv].mac,
                            ttp_mac_addrs[iv].age,
                            ttp_mac_addrs[iv].zon == ttp_myzn ? "  local" : "");
            if (n < 0 || n >= bs - sc) {
                return sc;
            }
            sc += n;
        }
        if (bs < sc) {
            return -EMSGSIZE;
        }
    }

    return sc;
}

static const struct kernel_param_ops ttp_param_mactbl_ops = {
    .set = ttp_param_mactbl_set,
    .get = ttp_param_mactbl_get,
};

module_param_cb (mactbl, &ttp_param_mactbl_ops, &ttp_mactbl_ct, 0644);
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
    dst_release (&rt4->dst); // ip_rt_put (rt4);
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

    switch (zcfg->ver) {
    case 4:
        rv = ttp_nh4_mac_get (zcfg);
        break;
    case 6:
        rv = ttp_nh6_mac_get (zcfg);
        break;
    default:
        TTP_LOG ("%s: Error: zn:%d Wrong gw-ver:%d\n", __FUNCTION__, zn, zcfg->ver);
        rv = -EINVAL;
        break;
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


static struct sk_buff *ttpip_skb_aloc (void)
{
    u8 *buf;
    struct sk_buff *skb;
    u16 frame_len;

    frame_len = ETH_HLEN + 12;

    if (!(skb = alloc_skb (frame_len + TTP_IP_HEADROOM, GFP_KERNEL))) {
        return NULL;
    }

    skb_reserve (skb, TTP_IP_HEADROOM);
    skb_reset_mac_header (skb);
    skb_set_network_header (skb, ETH_HLEN);
    skb->protocol = htons (TESLA_ETH_P_TTPOE);

    buf = skb_put (skb, 12);

    skb->len = max (frame_len, TTP_MIN_FRAME_LEN);
    skb_trim (skb, skb->len);
    skb_set_tail_pointer (skb, skb->len);
    skb->dev = ttpip_etype_tsla.dev;

    return skb;
}


static int ttpip_frm_recv (struct sk_buff *skb, struct net_device *dev,
                           struct packet_type *ptype, struct net_device *odev)
{
    int rc, zs = -1, zt = -1, iv = 0;
    u16 frame_len;
    struct iphdr *ipv4;
    struct ipv6hdr *ipv6;
    struct ttp_tsla_type_hdr *tth;
    struct ttp_tsla_shim_hdr *tsh;
    struct ttp_intf_cfg *zcfg, *intf;
    struct ethhdr *eth, neth = {0};
    struct ttp_mac_table *mtbl;

    if (ttp_shutdown) {
        TTP_LOG ("%s: <<- Tx frame dropped: ttp is shutdown\n", __FUNCTION__);
        kfree_skb (skb);
        return 0;
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
    skb_push (skb, ETH_HLEN);
    skb_reset_network_header (skb);
    skb_reset_mac_header (skb);
    TTP_DBG ("%s: ->> Rx frame: len:%d dev:%s\n", __FUNCTION__, skb->len, skb->dev->name);
    ttpip_pretty_print_data ("raw:", 16, false, skb->dev->name, skb->data, skb->len);
    tth = (struct ttp_tsla_type_hdr *)(eth + 1);
    tsh = (struct ttp_tsla_shim_hdr *)(tth + 1);
    if (ttp_verbose > 0) {
        ttp_print_eth_hdr (eth);
        ttp_print_tsla_type_hdr (tth);
        ttp_print_shim_hdr (tsh);
    }
    if (tth->tthl != TTP_PROTO_TTHL) {
        TTP_LOG ("%s: Drop frame: Incorrect TTHL: (%d)\n", __FUNCTION__, tth->tthl);
        goto end;
    }
    if (!tth->l3gw) {
        TTP_LOG ("%s: Drop frame: Improper ingress gw frame: 'l3gw' flag not set\n",
                 __FUNCTION__);
        goto end;
    }

    /* decode shim src/dst_node fields */
    ttp_mac_from_shim (neth.h_dest, tsh->dst_node);
    ttp_mac_from_shim (neth.h_source, tsh->src_node);

    /* lookup src-mac addr in mactbl */
    if ((mtbl = ttp_param_mactbl_find (neth.h_source))) {
        TTP_DBG ("%s: found src-mac:%*phC zn:%d\n", __FUNCTION__,
                 ETH_ALEN, mtbl->mac, mtbl->zon);
        zs = mtbl->zon;
    }
    /* lookup dst-mac addr in mactbl */
    if ((mtbl = ttp_param_mactbl_find (neth.h_dest))) {
        TTP_DBG ("%s: found dst-mac:%*phC zn:%d\n", __FUNCTION__,
                 ETH_ALEN, mtbl->mac, mtbl->zon);
        zt = mtbl->zon;
    }

    if (ether_addr_equal (neth.h_dest, ttpip_etype_tsla.dev->dev_addr)) {
        if ((rc = ttp_param_mactbl_add (ttp_myzn, neth.h_source, &iv))) {
            if (rc != EEXIST) {
                TTP_LOG ("`-> Error: mac-table full (rv:%d)\n", rc);
                goto end;
            }
        }
        TTP_DBG ("%s: gw_mac_adv: zn:%d  mac:%*phC%s\n", __FUNCTION__, ttp_myzn,
                 ETH_ALEN, neth.h_source, rc == EEXIST ? "" : " (new)");
        goto end;
    }

    /* use old hard-coded-table to lookup zone if mactbl lookup failed above */
    if (zs == -1) {
        if ((zs = ttp_zone_from_shim (tsh->src_node)) < 0) {
            TTP_LOG ("%s: Drop frame: error getting src zone from shim-header\n",
                     __FUNCTION__);
            goto end;
        }
    }
    if (zt == -1) {
        if ((zt = ttp_zone_from_shim (tsh->dst_node)) < 0) {
            TTP_LOG ("%s: Drop frame: error getting dst zone from shim-header\n",
                     __FUNCTION__);
            goto end;
        }
    }

    if (zs == zt) {
        TTP_LOG ("%s: Drop frame: src-node and dst-node are in same zone (%d)\n",
                 __FUNCTION__, zs);
        goto end;
    }
    if (!(zcfg = ttp_intf_cfg_get (zt))) {
        TTP_LOG ("%s: Drop frame: error getting zone config from target zone (%d)\n",
                 __FUNCTION__, zt);
        goto end;
    }

    TTP_DBG ("->> ingress-gw: ttp->ipv%d zn:%d->%d len:%d dev:%s\n", zcfg->ver,
             zs, zt, skb->len, skb->dev->name);
    skb_pull (skb, ETH_HLEN);
    skb_pull (skb, (tth->tthl * 4)); /* tthl is defined as number of 32bit blocks */

    if (zcfg->ver == 4) {
        skb_push (skb, sizeof (struct iphdr));

        ipv4 = (struct iphdr *)skb->data;
        memset (ipv4, 0, sizeof (*ipv4));

        ipv4->version = 4;
        ipv4->ihl = 5;
        ipv4->ttl = 9;
        ipv4->protocol = IPPROTO_TTP;
        if (!(intf = ttp_intf_get (zcfg, 4))) {
            TTP_LOG ("`->Error: no interface for device:%s, using fake-sip\n",
                     zcfg->dev->name);
            in4_pton ("10.0.0.1", -1, (u8 *)&ipv4->saddr, -1, NULL);
        }
        else {
            ipv4->saddr = intf->ip4.s_addr;
        }
        ipv4->daddr = zcfg->ip4.s_addr;
        frame_len = ETH_HLEN + sizeof (struct iphdr) + ntohs (tsh->length);
        frame_len = max (frame_len, TTP_MIN_FRAME_LEN);
        ipv4->tot_len = htons (frame_len - ETH_HLEN);
        ipv4->check = ip_fast_csum ((unsigned char *)ipv4, ipv4->ihl);
        if (ttp_verbose > 0) {
            ttp_print_ipv4_hdr (ipv4);
        }
    }
    else if (zcfg->ver == 6) {
        skb_push (skb, sizeof (struct ipv6hdr));

        ipv6 = (struct ipv6hdr *)skb->data;
        memset (ipv6, 0, sizeof (*ipv6));

        ipv6->version = 6;
        ipv6->nexthdr = IPPROTO_TTP;
        ipv6->hop_limit = 9;
        if (!(intf = ttp_intf_get (zcfg, 6))) {
            TTP_LOG ("`->Error: NO interface for device:%s, using fake-sip\n",
                     zcfg->dev->name);
            in6_pton ("fe80::1", -1, (u8 *)&ipv6->saddr, -1, NULL); /* HACK FIXME */
        }
        else {
            ipv6->saddr = intf->ip6;
        }
        ipv6->daddr = zcfg->ip6;
        frame_len = ETH_HLEN + sizeof (struct ipv6hdr) + ntohs (tsh->length);
        frame_len = max (frame_len, TTP_MIN_FRAME_LEN);
        ipv6->payload_len = htons (frame_len - ETH_HLEN - sizeof (struct ipv6hdr));
        if (ttp_verbose > 0) {
            ttp_print_ipv6_hdr (ipv6);
        }
    }
    else {
        TTP_LOG ("`->Error: Unknown IP version for gw - frame dropped\n");
        goto end;
    }

    skb_push (skb, ETH_HLEN);
    eth = (struct ethhdr *)skb->data;
    if (!is_valid_ether_addr (zcfg->mac)) {
        TTP_LOG ("`->Invalid gw-mac:%*pM, Drop frame: len:%d dev:%s\n",
                 ETH_ALEN, zcfg->mac, skb->len, skb->dev->name);
        ttp_nhmac_get (zt); /* trigger arp, no timers are kicked off */
        goto end;
    }

    memcpy (eth->h_source, zcfg->dev->dev_addr, ETH_ALEN);
    memcpy (eth->h_dest, zcfg->mac, ETH_ALEN);
    if (zcfg->ver == 4) {
        eth->h_proto = htons (ETH_P_IP);
    }
    else if (zcfg->ver == 6) {
        eth->h_proto = htons (ETH_P_IPV6);
    }

    skb->dev = zcfg->dev;    /* forward to gateway */
    skb_trim (skb, max (frame_len, TTP_MIN_FRAME_LEN));
    ttpip_pretty_print_data ("raw:", 16, true, skb->dev->name,
                             skb->data, skb->len);
    TTP_DBG ("`<<- Tx packet: len:%d dev:%s\n", skb->len, skb->dev->name);

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
    struct ttp_tsla_shim_hdr *tsh;
    struct ttp_tsla_type_hdr *tth;
    struct ethhdr *eth, neth = {0};

    if (ttp_shutdown) {
        TTP_LOG ("%s: ->> Rx pkt dropped: ttp is shutdown\n", __FUNCTION__);
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
    skb_push (skb, ETH_HLEN);
    TTP_DBG ("%s: ->> Rx pkt: len:%d dev:%s\n", __FUNCTION__,
             skb->len, skb->dev->name);
    ttpip_pretty_print_data ("raw:", 16, false, skb->dev->name,
                             (u8 *)eth, skb->len);
    if (ttp_verbose > 0) {
        ttp_print_eth_hdr (eth);
    }
    skb_pull (skb, ETH_HLEN);
    if (eth->h_proto == htons (ETH_P_IP)) {
        if (ttp_verbose > 0) {
            ttp_print_ipv4_hdr (ipv4);
        }
        tot_len = ntohs (ipv4->tot_len);
        skb_pull (skb, (ipv4->ihl * 4)); /* ihl is number of 32bit blocks */
        tsh = (struct ttp_tsla_shim_hdr *)(ipv4 + 1);
    }
    else if (eth->h_proto == htons (ETH_P_IPV6)) {
        if (ttp_verbose > 0) {
            ttp_print_ipv6_hdr (ipv6);
        }
        tot_len = ntohs (ipv6->payload_len) + sizeof (struct ipv6hdr);
        skb_pull (skb, (40)); /* ipv6 header-len is 'defined' 40 bytes */
        tsh = (struct ttp_tsla_shim_hdr *)(ipv6 + 1);
    }
    if (ttp_verbose > 0) {
        ttp_print_shim_hdr (tsh);
    }
    ttp_mac_from_shim (neth.h_dest, tsh->dst_node);
    ttp_mac_from_shim (neth.h_source, tsh->src_node);
    skb->dev = ttpip_etype_tsla.dev;
    skb_push (skb, sizeof (struct ttp_tsla_type_hdr));
    tth = (struct ttp_tsla_type_hdr *)skb->data;
    tth->styp = 0;
    tth->vers = 0;
    tth->tthl = TTP_PROTO_TTHL;
    tth->l3gw = true; /* always set gw flag */
    tth->resv = 0;
    tth->tot_len = htons (skb->len);
    memset (tth->pad, 0, sizeof (tth->pad));
    skb_push (skb, ETH_HLEN);
    eth = (struct ethhdr *)skb->data;
    memcpy (eth->h_source, ttpip_etype_tsla.dev->dev_addr, ETH_ALEN);
    memcpy (eth->h_dest, neth.h_dest, ETH_ALEN);
    eth->h_proto = htons (TESLA_ETH_P_TTPOE);
    skb_trim (skb, max ((u16)(ETH_HLEN + tot_len), TTP_MIN_FRAME_LEN));
    skb->len = max ((u16)skb->len, TTP_MIN_FRAME_LEN);
    skb_reset_network_header (skb);
    skb_reset_mac_header (skb);
    if (ttp_verbose > 0) {
        ttp_print_eth_hdr (eth);
        ttp_print_tsla_type_hdr (tth);
        ttp_print_shim_hdr (tsh);
    }
    if ((zs = ttp_zone_from_shim (tsh->src_node)) < 0) {
        TTP_LOG ("%s: Drop pkt: error getting zone from shim-header\n",
                 __FUNCTION__);
        goto end;
    }
    if ((zt = ttp_zone_from_shim (tsh->dst_node)) < 0) {
        TTP_LOG ("%s: Drop pkt: error getting zone from shim-header\n",
                 __FUNCTION__);
        goto end;
    }
    if (zs == zt) {
        TTP_LOG ("%s: Drop pkt: src-node and dst-node are in same zone (%d)\n",
                 __FUNCTION__,
                 zs);
        goto end;
    }
    TTP_DBG ("<<-- egress-gw: ttp<-ipv%d zn:%d<-%d len:%d dev:%s\n", ver,
             zt, zs, skb->len, skb->dev->name);
    ttpip_pretty_print_data ("raw:", 16, true, skb->dev->name,
                             skb->data, skb->len);
    TTP_DBG ("<<- Tx frame: len:%d dev:%s\n", skb->len, skb->dev->name);
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
    int iv;
    struct sk_buff *skb;
    struct ethhdr *eth;
    struct ttp_tsla_type_hdr *tth;
    struct ttp_tsla_shim_hdr *tsh;
    u8 *opcode;

    if (!(skb = ttpip_skb_aloc ())) {
        return;
    }

    eth = (struct ethhdr *)skb_mac_header (skb);
    memcpy (eth->h_source, ttpip_etype_tsla.dev->dev_addr, ETH_ALEN);
    memcpy (eth->h_dest, ttpip_etype_tsla.dev->dev_addr, ETH_ALEN);
    eth->h_dest[0] |= 0x3; /* convert to multicast link-local mac address */
    eth->h_proto = htons (TESLA_ETH_P_TTPOE);

    tth = (struct ttp_tsla_type_hdr *)(eth + 1);
    tth->styp = 0;
    tth->vers = 0;
    tth->tthl = TTP_PROTO_TTHL;
    tth->l3gw = true; /* always set gw flag */
    tth->resv = 0;
    tth->tot_len = 0;
    memset (tth->pad, 0, sizeof (tth->pad));

    tsh = (struct ttp_tsla_shim_hdr *)(tth + 1);
    memmove (tsh->src_node, &ttpip_etype_tsla.dev->dev_addr[3], ETH_ALEN/2);
    memmove (tsh->dst_node, eth->h_dest, ETH_ALEN/2);
    tsh->length = htons (26);

    opcode = (u8 *)(tsh + 1);
    *opcode = 2; /* OPEN_NACK */

    ttpip_pretty_print_data ("raw:", 16, true, skb->dev->name,
                             skb->data, skb->len);
    TTP_DBG ("<<- Tx link-local mac-multicast gw-mac-adv frame: len:%d dev:%s\n",
             skb->len, skb->dev->name);

    skb_reset_network_header (skb);
    skb_reset_mac_header (skb);
    dev_queue_xmit (skb);

    for (iv = 0; iv < ttp_mactbl_ct; iv++) {
        if (!is_zero_ether_addr (ttp_mac_addrs[iv].mac)) {
            if (ttp_mac_addrs[iv].age >= TTP_MAC_AGEOUT_MAX) {
                memset (&ttp_mac_addrs[iv], 0, sizeof (struct ttp_mac_table));
                continue;
            }
            ttp_mac_addrs[iv].age++;
        }
    }

    ttp_gw_mac_adv_timer_head.expires = jiffies + msecs_to_jiffies (1000);
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

        /* look for ipv4 address */
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
                zcfg = &ttp_zones[zn];
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

        /* look for ipv6 address */
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
                zcfg = &ttp_zones[zn];
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
    if (!ttp_zones[ttp_myzn].dev) {
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
             "            ttp-if:'%s' mac:%*pM\n", __FUNCTION__, ttp_zones[ttp_myzn].ver,
             ttp_zones[ttp_myzn].dev->name, ETH_ALEN, ttp_zones[ttp_myzn].dev->dev_addr,
             ttpip_etype_tsla.dev->name, ETH_ALEN, ttpip_etype_tsla.dev->dev_addr);

    timer_setup (&ttp_gw_mac_adv_timer_head, &ttp_gw_mac_adv_timer_cb, 0);
    ttp_gw_mac_adv_timer_head.expires = jiffies + 100;
    add_timer (&ttp_gw_mac_adv_timer_head);

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
