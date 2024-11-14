// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Tesla Inc. All rights reserved.
 *
 * TTP-GW   A sample implementation of Tesla Transport Protocol Gateway (TTP-GW) that
 *          works with a network of Linux machines running the TTPoE kernel module and
 *          provides a way to allow islands of TTPoE in separate Layer-2 Ethernet
 *          networks to function seamlessly over an IPv4 network. This is work under
 *          development.
 *
 *          This public release of the TTP software implementation is aligned with the
 *          patent disclosure and public release of the main TTP Protocol specification.
 *          Users of this software module must take into consideration those disclosures
 *          in addition to the license agreement mentioned here.
 *
 * Authors: Diwakar Tundlam <dntundlam@tesla.com>
 *
 * This software is licensed under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation, and may be copied, distributed, and
 * modified under those terms.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; Without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 */

#ifndef MODULE
#define MODULE
#endif

#ifndef __KERNEL__
#define __KERNEL__
#endif

#include <linux/skbuff.h>
#include <linux/version.h>
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
#include <net/addrconf.h>
#include <uapi/linux/ipv6.h>

#include <ttp.h>

#include "ttpip.h"


char *ttp_dev;
int   ttp_verbose  = -1;
int   ttp_shutdown =  1; /* 'DOWN' by default - enabled at init after checking */
int   ttp_drop_pct =  0; /* drop percent = 0% by default */

const u32 Tesla_Mac_Oui  = TESLA_MAC_OUI;

struct ttp_timer ttp_nh_mac_tmr = {.exp = TTP_NH_MAC_TRY_TMR, .max = 5};
struct ttp_timer ttp_gw_ctl_tmr = {.exp = TTP_GW_CTL_ADV_TMR};

static int ttpip_pkt_recv (struct sk_buff *skb, struct net_device *dev,
                           struct packet_type *ptype, struct net_device *odev);
static int ttpip_frm_recv (struct sk_buff *skb, struct net_device *dev,
                           struct packet_type *ptype, struct net_device *odev);
static void ttp_gw_ctl_send (const char *mac, enum ttp_mac_opcodes oc);
static void ttp_gw_ctl_recv (const char *mac, const struct ttp_tsla_shim_hdr *tsh);

static struct packet_type ttpip_etype_lyr3 __read_mostly = {
    .dev  = NULL,   /* set via module-param */
    .type = 0,      /* match ETH_P_IP or ETH_P_IPV6 dep on my-gw-ip ver in gwips */
    .func = ttpip_pkt_recv,
    .ignore_outgoing = true,
};
static struct packet_type ttpip_etype_tsla __read_mostly = {
    .dev  = NULL,                      /* set via module-param 'dev' */
    .type = htons (TESLA_ETH_P_TTPOE), /* match ttpoe ethernet-encap frames */
    .func = ttpip_frm_recv,
    .ignore_outgoing = true,
};

static int          ttp_myzn;
static int          ttp_num_gwips;
struct ttp_intf_cfg ttp_zones[TTP_MAX_NUM_ZONES];

struct mutex        ttp_mactbl_mutx;
struct mutex        ttp_zoncfg_mutx;
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


static inline bool ttpip_is_ttp_dev (const u8 *name)
{
    return !strncmp (name, ttp_dev, IFNAMSIZ);
}


static void ttpip_mcast_mac_create (u8 *mac)
{
    u32 imac; /* holds lower 3 bytes - similar to shim */

    imac = htonl (0xFFFFFF << 8); /* makes each lower 3 byte = 0xff */
    ttp_prepare_mac_with_oui (mac, Tesla_Mac_Oui, (u8 *)&imac);
    mac[0] |= 0x3; /* convert to multicast link-local mac address */
}


static struct sk_buff *ttpip_skb_aloc (void)
{
    struct sk_buff *skb;
    u16 frame_len;

    frame_len = ETH_HLEN + 12;

    if (!(skb = alloc_skb (frame_len + TTP_IP_HEADROOM, GFP_ATOMIC))) {
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


static void ttpip_pretty_print_data (const u8 *caption, bool tx,
                                     const u8 *devname, const u8 *buf,
                                     int buflen, int trmlen)
{
    int len = !trmlen ? buflen : trmlen;

    TTP_DB2 ("%s %s dev: %s len: %d%s\n",
             caption, tx ? "<<- Tx" : "->> Rx", devname, buflen,
             (trmlen && (trmlen != buflen)) ? " (trimmed)" : "");
    do {
        TTP_DB2 ("%s %*ph\n", caption, min (len, 16), buf);
        buf += 16;
        len -= 16;
    } while (len > 0);
}


static inline bool ttp_zone_valid (int zn)
{
    bool rv;

    rv = !!((ttp_num_gwips) &&
            (zn > 0 && zn < TTP_MAX_NUM_ZONES) &&
            (ttp_zones[zn].ver == 4 || ttp_zones[zn].ver == 6));

    return rv;
}


static inline bool ttp_myzone (int zn)
{
    bool rv;

    rv = !!(ttp_num_gwips && (ttp_myzn == zn));
    return rv;
}


static inline struct ttp_intf_cfg *ttp_zcfg (int zn)
{
    struct ttp_intf_cfg *zcfg = NULL;

    if (ttp_zone_valid (zn)) {
        zcfg = &ttp_zones[zn];
    }
    return zcfg;
}


static inline struct ttp_intf_cfg *ttp_myzcfg (void)
{
    return ttp_zcfg (ttp_myzn);
}


static inline int ttp_param_dummy_set (const char *val, const struct kernel_param *kp)
{
    TTP_LOG ("%s: Error: kernel param not settable\n", __FUNCTION__);
    return -EPERM;
}


/* Scan ipv4 addresses */
static void ttp_param_zones_scan_ipv4 (const struct net_device *dev)
{
    int zn;
    struct ttp_intf_cfg *zcfg;
    struct in_ifaddr *ifa4;

    TTP_LOG ("  `->Scanning ipv4 addresses: on dev:%s\n", dev->name);

    rcu_read_lock ();
    for (ifa4 = rcu_dereference (dev->ip_ptr->ifa_list); ifa4;
         ifa4 = rcu_dereference (ifa4->ifa_next)) {

        TTP_LOG ("    `->ipv4:%pI4/%d%s\n", &ifa4->ifa_address, ifa4->ifa_prefixlen,
                 ttpip_is_ttp_dev (dev->name) ? " (ttp-dev)" : "");

        for (zn = 1; zn < TTP_MAX_NUM_ZONES; zn++) {
            if (!(zcfg = ttp_zcfg (zn))) {
                continue;
            }
            if ((zcfg->ver != 4) || (zcfg->da4.s_addr != ifa4->ifa_address)) {
                continue;
            }
            if (zcfg->dev) {
                TTP_LOG ("Error: zn:%d repeated ipv4 device: (dev:%s)\n", zn, dev->name);
                break;
            }

            zcfg->zon = ttp_myzn = zn;
            zcfg->dev = dev;

            ttpip_etype_lyr3.dev = (struct net_device *)dev;
            ttpip_etype_lyr3.type = htons (ETH_P_IP);

            zcfg->pfl = ifa4->ifa_prefixlen;
            memcpy (zcfg->mac, zcfg->dev->dev_addr, ETH_ALEN);

            TTP_LOG ("      `->Found zone: my_zn:%d dev:%s ip4:%pI4/%d\n",
                     ttp_myzn, dev->name, &zcfg->da4, zcfg->pfl);
            break;
        }
    }
    rcu_read_unlock ();
}


/* Scan ipv6 addresses */
static void ttp_param_zones_scan_ipv6 (const struct net_device *dev)
{
    int zn;
    struct list_head *lhp;
    struct ttp_intf_cfg *zcfg;
    struct inet6_ifaddr *ifa6;

    TTP_LOG ("  `->Scanning ipv6 addresses: on dev:%s\n", dev->name);

    rcu_read_lock ();
    list_for_each (lhp, &dev->ip6_ptr->addr_list) {
        if (!(ifa6 = list_entry (lhp, struct inet6_ifaddr, if_list))) {
            break;
        }

        TTP_LOG ("    `->ipv6:%pI6c/%d%s\n", &ifa6->addr, ifa6->prefix_len,
                 ttpip_is_ttp_dev (dev->name) ? " (ttp-dev)" : "");

        for (zn = 1; zn < TTP_MAX_NUM_ZONES; zn++) {
            if (!(zcfg = ttp_zcfg (zn))) {
                continue;
            }
            if ((zcfg->ver != 6) || ipv6_addr_cmp (&zcfg->da6, &ifa6->addr)) {
                continue;
            }
            if (zcfg->dev) {
                TTP_LOG ("Error: zn:%d repeated ipv6 device: (dev:%s)\n", zn, dev->name);
                break;
            }

            zcfg->zon = ttp_myzn = zn;
            zcfg->dev = dev;

            ttpip_etype_lyr3.dev = (struct net_device *)dev;
            ttpip_etype_lyr3.type = htons (ETH_P_IPV6);

            zcfg->pfl = ifa6->prefix_len;
            memcpy (zcfg->mac, zcfg->dev->dev_addr, ETH_ALEN);

            TTP_LOG ("      `->Found zone: my_zn:%d dev:%s ip6:%pI6c/%d\n",
                     ttp_myzn, dev->name, &zcfg->da6, zcfg->pfl);
            break;
        }
    }
    rcu_read_unlock ();
}


static int ttp_param_gwips_set (const char *val, const struct kernel_param *kp)
{
    int len, rv;
    int zn;
    char save;
    struct ttp_intf_cfg *zcfg;
    struct net_device *dev;

    if (!(len = strcspn (val, "\n"))) {
        return 0;
    }
    if (((char *)val)[len] == '\n') {
        ((char *)val)[len] = '\0'; /* eat any trailing newline in val */
    }
    if (!mutex_trylock (&ttp_zoncfg_mutx)) {
        TTP_LOG ("%s: Error: zon-mutex trylock failed\n", __FUNCTION__);
        return -EBUSY;
    }

    TTP_LOG ("%s: Parsing gwips from '%s'\n", __FUNCTION__, val);

    /* Force re-initialization of zones */
    ttp_num_gwips = 0;
    memset (ttp_zones, 0, sizeof (ttp_zones));
    TTP_LOG ("`->: Zeroed out %zu bytes: %zu ttp_zones\n", sizeof (struct ttp_intf_cfg),
             sizeof (ttp_zones) / sizeof (struct ttp_intf_cfg));

    for (zn = 1; zn < TTP_MAX_NUM_ZONES; zn++) {
        zcfg = &ttp_zones[zn]; /* pick array entry directly (others: use ttp_zcfg()) */
        if ((len = strcspn (val, ","))) {
            save = val[len];
            if (save == ',') {
                ((char *)val)[len] = '\0'; /* eat any trailing newline in val */
            }
            if ((rv = in4_pton (val, -1, (u8 *)&zcfg->da4, -1, NULL))) {
                zcfg->ver = 4;
                zcfg->zon = zn;
                ttp_num_gwips++;
                TTP_LOG ("  `->zn:%d ip4:%pI4\n", zn, &zcfg->da4);
            }
            else if ((rv = in6_pton (val, -1, (u8 *)&zcfg->da6, -1, NULL))) {
                zcfg->ver = 6;
                zcfg->zon = zn;
                ttp_num_gwips++;
                TTP_LOG ("  `->zn:%d ip6:%pI6c\n", zn, &zcfg->da6);
            }
        }

        val += len + 1;
        if ((save == ',') && (zn == TTP_MAX_NUM_ZONES - 1)) {
            TTP_LOG ("`->Ignoring zones beyond max=%d\n", TTP_MAX_NUM_ZONES - 1);
            break;
        }
        if (save != ',') {
            break;
        }
    }
    if (!ttp_num_gwips) {
        mutex_unlock (&ttp_zoncfg_mutx);
        return -EINVAL;
    }

    BUG_ON (ttp_num_gwips >= TTP_MAX_NUM_ZONES);

    /* Scan network devices, interfaces, and IP addresses:
     * Caution: Only discovers devices in default network namespace (netns) */
    ttp_dev_read_lock ();
    TTP_LOG ("%s: Scanning network devices:\n", __FUNCTION__);
    for (dev = first_net_device (&init_net); dev; dev = next_net_device (dev)) {
        if (dev->flags & IFF_LOOPBACK) {
            continue;
        }
        if (!(dev->flags & IFF_UP)) {
            continue;
        }
        TTP_LOG ("`->Found device: dev:%s id:%d mac:%*phC\n", dev->name, dev->ifindex,
                 ETH_ALEN, dev->dev_addr);

        ttp_param_zones_scan_ipv4 (dev);
        ttp_param_zones_scan_ipv6 (dev);
    }
    ttp_dev_read_unlock ();

    if (!ttp_shutdown) { /* if enabled reset nh resolution timer state and kick it off */
        ttp_nh_mac_tmr.rst = true;
        mod_timer (&ttp_nh_mac_tmr.tmh, jiffies + msecs_to_jiffies (100));
    }

    mutex_unlock (&ttp_zoncfg_mutx);
    return 0;
}

static int ttp_param_gwips_get (char *buf, const struct kernel_param *kp)
{
    int zn, sc = 0, bs = PAGE_SIZE;
    struct ttp_intf_cfg *zcfg;
    char dastr[64], *via;

    if (!mutex_trylock (&ttp_zoncfg_mutx)) {
        TTP_LOG ("%s: Error: zon-mutex trylock failed\n", __FUNCTION__);
        return -EBUSY;
    }

    BUG_ON (!ttp_num_gwips);
    TTP_SNPRINTF (BLUE "%2s  %26s  %-17s  %-8s %7s\n" CLEAR,
                  "zn", "ttp-layer3-gateway-ip", "next-hop-mac-addr", "device", "route");

    for (zn = 1; zn < TTP_MAX_NUM_ZONES; zn++) {
        if (!(zcfg = ttp_zcfg (zn))) {
            continue;
        }
        if (zcfg->ver == 4) {
            snprintf (dastr, 64, "%pI4", &zcfg->da4);
            via = zcfg->gwy ? "rt-v4" : "dir-arp";
        }
        else if (zcfg->ver == 6) {
            snprintf (dastr, 64, "%pI6c", &zcfg->da6);
            via = zcfg->gwy ? "rt-v6" : "dir-nd6";
        }
        else {
            continue;
        }
        TTP_SNPRINTF ("%s%2d%c %26s  %*pM  %-8s %7s\n" CLEAR,
                      ttp_myzone (zn) ? CYAN : !is_valid_ether_addr (zcfg->mac) ?
                      RED : zcfg->gwy ? zcfg->ver == 4 ? GREEN : YELLOW : NOCOLOR,
                      zn, ttp_myzone (zn) ? '*' : ' ', dastr, ETH_ALEN, zcfg->mac,
                      zcfg->dev ? zcfg->dev->name : "(none)",
                      ttp_myzone (zn) ? "self" : !is_valid_ether_addr (zcfg->mac) ?
                      "unres" : via);
    }

    mutex_unlock (&ttp_zoncfg_mutx);
    return sc;
}

static const struct kernel_param_ops ttp_param_gwips_ops = {
    .set = ttp_param_gwips_set,
    .get = ttp_param_gwips_get,
};

module_param_cb (gwips, &ttp_param_gwips_ops, &ttp_num_gwips, 0644);
MODULE_PARM_DESC (gwips, "    set list of ttp gateway ip-addreses per zone (1,2,3,..):\n"
                  "                          e.g. gwips=10.0.1.1,10.0.2.2,10.0.3.3,..");


static int ttp_param_intfs_get (char *buf, const struct kernel_param *kp)
{
    int sc = 0, bs = PAGE_SIZE;
    struct net_device *dev;
    struct list_head *lhp;
    struct in_ifaddr *ifa4;
    struct inet6_ifaddr *ifa6;

    TTP_SNPRINTF (BLUE "%2s  %-8s %29s  %17s\n" CLEAR,
                  "if", "device", "interface-ip-address", "device-mac-addr");

    ttp_dev_read_lock ();
    for (dev = first_net_device (&init_net); dev; dev = next_net_device (dev)) {
        if (dev->flags & IFF_LOOPBACK) {
            continue;
        }
        if (!(dev->flags & IFF_UP)) {
            continue;
        }

        rcu_read_lock (); /* ver-6.9+: dev_read_lock is rcu_read_lock; lock 2wice ok */
        for (ifa4 = rcu_dereference (dev->ip_ptr->ifa_list); ifa4;
             ifa4 = rcu_dereference (ifa4->ifa_next)) {
            TTP_SNPRINTF ("%s%2d  %-8s %26pI4/%-2d  %*pM\n" CLEAR,
                          ttpip_is_ttp_dev (dev->name) ? RED : GREEN,
                          dev->ifindex, dev->name,
                          &ifa4->ifa_address, ifa4->ifa_prefixlen,
                          ETH_ALEN, dev->dev_addr);
        }

        list_for_each (lhp, &dev->ip6_ptr->addr_list) {
            if (!(ifa6 = list_entry (lhp, struct inet6_ifaddr, if_list))) {
                break;
            }
            TTP_SNPRINTF ("%s%2d  %-8s %26pI6c/%-2d  %*pM\n" CLEAR,
                          ttpip_is_ttp_dev (dev->name) ? RED : NOCOLOR,
                          dev->ifindex, dev->name,
                          &ifa6->addr, ifa6->prefix_len,
                          ETH_ALEN, dev->dev_addr);
        }
        rcu_read_unlock ();
    }
    ttp_dev_read_unlock ();
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
    int sc = 0, bs = PAGE_SIZE;
    struct net_device *dev;

    TTP_SNPRINTF (BLUE "%2s  %-8s %17s  %s\n" CLEAR, "if", "device",
                  "device-mac-addr", "device-type");

    for (dev = first_net_device (&init_net); dev; dev = next_net_device (dev)) {
        if (dev->flags & IFF_LOOPBACK) {
            continue;
        }
        if (!(dev->flags & IFF_UP)) {
            continue;
        }
        TTP_SNPRINTF ("%s%2d  %-8s %*pM  %s\n" CLEAR,
                      ttpip_is_ttp_dev (dev->name) ? RED : NOCOLOR,
                      dev->ifindex,
                      dev->name, ETH_ALEN, dev->dev_addr,
                      ttpip_is_ttp_dev (dev->name) ? "ttp-dev" : "");
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

    /* keep hash-values in ascending order */
    t1 = ttp_tag_index_hash_calc (m1);
    t2 = ttp_tag_index_hash_calc (m2);
    if (t1 < t2) {
        return 1;
    }
    else if (t1 > t2) {
        return -1;
    }

    /* hash-values equal */
    return memcmp (m1, m2, ETH_ALEN);
}

static struct ttp_mactable *ttp_mactbl_rbtree_add (const u8 *mac)
{
    struct rb_node **new, *parent = NULL;
    struct ttp_mactable *lmc;
    int cmp;

    if (!mutex_trylock (&ttp_mactbl_mutx)) {
        TTP_LOG ("%s: Error: mac-mutex trylock failed [mac %*pM]\n", __FUNCTION__,
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
            lmc->vld = 1; /* can resurrect a DEAD entry */
            goto end;
        }
    }

    lmc = NULL;
    if (ttp_mactbl_ct >= TTP_MAC_TABLE_SIZE) {
        TTP_LOG ("%s: Error: table full(%d) [mac %*pM]\n", __FUNCTION__,
                 ttp_mactbl_ct, ETH_ALEN, mac);
        goto end;
    }
    if (!(lmc = kzalloc (sizeof (*lmc), GFP_ATOMIC))) {
        TTP_LOG ("%s: Error: kzalloc failed [mac %*pM]\n", __FUNCTION__,
                 ETH_ALEN, mac);
        goto end;
    }

    lmc->vld = 1;
    rb_link_node (&lmc->rbn, parent, new);
    rb_insert_color (&lmc->rbn, &ttp_mactbl_rbroot);

    ttp_mactbl_ct++;
    ether_addr_copy (lmc->mac, mac);

end:
    mutex_unlock (&ttp_mactbl_mutx);
    return lmc;
}

/* returns 'true' if a mac-delete was done, else returns 'false' */
static bool ttp_mactbl_rbtree_del (const u8 *mac)
{
    struct rb_node **new, *parent = NULL;
    struct ttp_mactable *lmc;
    bool rv = false;
    int cmp;

    if (!mutex_trylock (&ttp_mactbl_mutx)) {
        TTP_LOG ("%s: Error: mac-mutex trylock failed [mac %*pM]\n", __FUNCTION__,
                 ETH_ALEN, mac);
        return rv;
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
            rv = true;
            break;
        }
    }

    mutex_unlock (&ttp_mactbl_mutx);
    return rv;
}

static struct ttp_mactable *ttp_mactbl_rbtree_find (const u8 *mac)
{
    struct rb_node **new, *parent = NULL;
    struct ttp_mactable *lmc;
    int cmp;

    if (!mutex_trylock (&ttp_mactbl_mutx)) {
        TTP_LOG ("%s: Error: mac-mutex trylock failed [mac %*pM]\n", __FUNCTION__,
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
    mutex_unlock (&ttp_mactbl_mutx);
    return lmc;
}


static struct ttp_mactable *ttp_mactbl_rbtree_find_next (const struct ttp_mactable *mct)
{
    struct rb_node *rb = !mct ? rb_first (&ttp_mactbl_rbroot) : rb_next (&mct->rbn);

    return rb ? rb_entry (rb, struct ttp_mactable, rbn) : NULL;
}

static struct ttp_mactable *ttp_mactbl_find (const char *mac)
{
    if (!is_valid_ether_addr (mac)) {
        return NULL;
    }
    return ttp_mactbl_rbtree_find (mac);
}


static int ttp_mactbl_add (int zn, const char *mac, enum ttp_mac_opcodes oc)
{
    struct ttp_mactable *mct;

    if (!mac) {
        return -EINVAL;
    }
    if (!ttp_zone_valid (zn)) {
        return -EINVAL;
    }
    if (!is_valid_ether_addr (mac)) {
        return -EINVAL;
    }
    if (!(mct = ttp_mactbl_rbtree_add (mac))) {
        return -ENOMEM;
    }

    switch (oc) {
    case TTP_GW_CTL_OP_LOCAL_ADD:
        /* send locally added mac to other gateways */
        ttp_gw_ctl_send (mac, TTP_GW_CTL_OP_REMOTE_ADD);
        mct->rem = 0;
        break;
    case TTP_GW_CTL_OP_GATEWAY_SLF:
        mct->gwf = 1;
        mct->prm = 1;
        break;
    case TTP_GW_CTL_OP_GATEWAY_ADD:
        mct->gwf = 1;
        mct->rem = 1;
        break;
    case TTP_GW_CTL_OP_REMOTE_ADD:
        mct->rem = 1;
        break;
    default:
        BUG_ON (1);
        break;
    }

    mct->age = 0;
    if (ttp_zone_valid (mct->zon)) {            /* existing entry */
        return EEXIST;
    }
    mct->zon = zn;

    return 0;
}


static int ttp_mactbl_del (int zn, const char *mac, enum ttp_mac_opcodes oc)
{
    if (!mac) {
        return 0;
    }
    if (!is_valid_ether_addr (mac)) {
        return 0;
    }

    switch (oc) {
    case TTP_GW_CTL_OP_LOCAL_DEL:
        break;
    case TTP_GW_CTL_OP_REMOTE_DEL:
        break;
    default:
        BUG_ON (1);
        break;
    }

    return ttp_mactbl_rbtree_del (mac);
}


#define CLIFFX(ag,xx) ((ag) <(xx) ? 0: (ag)) /* to filter thrashing output at '0' age */
#define AGE2MS(ag) (CLIFFX (ag, 2) * TTP_GW_CTL_ADV_TMR)

#define TTP_PRINTF_COMMON(colr)                                 \
    do {                                                        \
        TTP_SNPRINTF ("%s%2d%c 0x%02x  %*pM  %c%c%c%c %6d   ",  \
                      colr,                                     \
                      mct->zon,                                 \
                      ttp_myzone (mct->zon) ? '*' : ' ',        \
                      ttp_tag_index_hash_calc (mct->mac),       \
                      ETH_ALEN, mct->mac,                       \
                      mct->vld ? 'v' : '-',                     \
                      mct->prm ? 'p' : '-',                     \
                      mct->rem ? 'r' : 'l',                     \
                      mct->gwf ? 'g' : '-',                     \
                      AGE2MS (mct->age));                       \
    } while (0)

#define TTP_PRINTF_LOCAL(colr, cond)                            \
    do {                                                        \
        struct ttp_mactable *mct = NULL;                        \
                                                                \
        while ((mct = ttp_mactbl_rbtree_find_next (mct))) {     \
            if ((cond)) {                                       \
                TTP_PRINTF_COMMON (colr);                       \
                TTP_SNPRINTF ("%7lld  %6d   %7lld  %6d\n",      \
                              mct->t.byt, mct->t.frm,           \
                              mct->r.byt, mct->r.frm);          \
            }                                                   \
        }                                                       \
    } while (0)

#define TTP_PRINTF_LLA6(colr, cond)                             \
    do {                                                        \
        struct ttp_mactable *mct = NULL;                        \
        struct in6_addr ip6;                                    \
                                                                \
        while ((mct = ttp_mactbl_rbtree_find_next (mct))) {     \
            if ((cond)) {                                       \
                TTP_PRINTF_COMMON (colr);                       \
                TTP_SNPRINTF ("%pI6c\n",                        \
                              ttp_mac2lla6 (&ip6, mct->mac));   \
            }                                                   \
        }                                                       \
    } while (0)

#define TTP_PRINTF_GWIP(colr, cond)                             \
    do {                                                        \
        struct ttp_mactable *mct = NULL;                        \
        struct ttp_intf_cfg *zcfg;                              \
                                                                \
        while ((mct = ttp_mactbl_rbtree_find_next (mct))) {     \
            if ((cond)) {                                       \
                TTP_PRINTF_COMMON (colr);                       \
                if ((zcfg = ttp_zcfg (mct->zon))) {             \
                    if (zcfg->ver == 4) {                       \
                        TTP_SNPRINTF ("%pI4\n", &zcfg->da4);    \
                    }                                           \
                    else if (zcfg->ver == 6) {                  \
                        TTP_SNPRINTF ("%pI6c\n", &zcfg->da6);   \
                    }                                           \
                }                                               \
                else {                                          \
                    TTP_SNPRINTF ("<none>\n");                  \
                }                                               \
            }                                                   \
        }                                                       \
    } while (0)

#define TTP_MACTBL_TALLY(cond)                                  \
    ({                                                          \
        int taly = 0;                                           \
                                                                \
        struct ttp_mactable *mct = NULL;                        \
        while ((mct = ttp_mactbl_rbtree_find_next (mct))) {     \
            if ((cond)) {                                       \
                taly++;                                         \
            }                                                   \
        }                                                       \
        taly;                                                   \
    })

#define TTP_MACTBL_LOCL(colr, cond, arg...)                     \
    do {                                                        \
        if (TTP_MACTBL_TALLY (cond)) {                          \
            TTP_SNPRINTF (arg);                                 \
            TTP_PRINTF_LOCAL (colr, cond);                      \
        }                                                       \
    } while (0)

#define TTP_MACTBL_LLA6(colr, cond, arg...)                     \
    do {                                                        \
        if (TTP_MACTBL_TALLY (cond)) {                          \
            TTP_SNPRINTF (arg);                                 \
            TTP_PRINTF_LLA6 (colr, cond);                       \
        }                                                       \
    } while (0)

#define TTP_MACTBL_GWIP(colr, cond, arg...)                     \
    do {                                                        \
        if (TTP_MACTBL_TALLY (cond)) {                          \
            TTP_SNPRINTF (arg);                                 \
            TTP_PRINTF_GWIP (colr, cond);                       \
        }                                                       \
    } while (0)


static int ttp_param_mactbl_get (char *buf, const struct kernel_param *kp)
{
    int sc = 0, bs = PAGE_SIZE;

    if (!ttp_mactbl_ct) {
        TTP_SNPRINTF ("<empty>\n");
        return sc;
    }
    if (!mutex_trylock (&ttp_mactbl_mutx)) {
        TTP_SNPRINTF ("%s: Error: mac-mutex trylock failed\n", __FUNCTION__);
        return sc;
    }

    TTP_SNPRINTF (BLUE "%2s  %4s  %17s  %4s %7s  %-25s\n", "zn", "hash",
                  "--- mac-addrs ---", "flag", "age(ms)", "next-hop-gateway");

    /* permanent gateway entries (self-gw): valid, PERMANENT, gateway, (rem=x) */
    TTP_MACTBL_GWIP (MAGENTA, mct->vld && mct->prm && mct->gwf,
                     GREEN "%27s  %4s %7s  %-25s\n", "Gateway MAC addresses:",
                     "flag", "age(ms)", "next-hop-gateway");
    /* other gateway entries: valid, NOT permanent, GATEWAY, (rem=x) */
    TTP_MACTBL_GWIP (GREEN, mct->vld && !mct->prm && mct->gwf, GREEN);

    /* remote entries: valid, not permanent, not gw, REMOTE */
    TTP_MACTBL_GWIP (YELLOW, mct->vld && !mct->prm && !mct->gwf && mct->rem,
                     YELLOW "%27s  %4s %7s  %-25s\n", "Remote Live MAC addresses:",
                     "flag", "age(ms)", "next-hop-gateway");

#if 0 /* show link-local-ipv6 addresses for local ttp end-points */
    /* local live entries: valid, not permanent, not gw, NOT remote */
    TTP_MACTBL_LLA6 (CYAN, !mct->age && mct->vld && !mct->prm && !mct->gwf && !mct->rem,
                     CYAN "%27s  %4s %7s  %s\n", "Local Live MAC addresses:",
                     "flag", "age(ms)", "link-local-ipv6-address");

    /* local aging entries: valid, not permanent, not gw, NOT remote */
    TTP_MACTBL_LLA6 (WHITE, mct->age && mct->vld && !mct->prm && !mct->gwf && !mct->rem,
                     WHITE "%27s  %4s %7s  %s\n", "Local Aging MAC addresses:",
                     "flag", "age(ms)", "link-local-ipv6-address");

    /* local dead entries: invalid / dead entries */
    TTP_MACTBL_LLA6 (BLUE, !mct->vld && !mct->gwf,
                     BLUE "%27s  %4s %7s  %s\n", "Local Dead MAC addresses:",
                     "flag", "age(ms)", "link-local-ipv6-address");
#else /* show tx/rx bytes/pkts for local ttp end-points */
    /* local live entries: valid, not permanent, not gw, NOT remote */
    TTP_MACTBL_LOCL (CYAN, !mct->age && mct->vld && !mct->prm && !mct->gwf && !mct->rem,
                     CYAN "%27s  %4s %7s  %s\n", "Local Live MAC addresses:",
                     "flag", "age(ms)", "tx-byts tx-pkts   rx-byts rx-pkts");

    /* local aging entries: valid, not permanent, not gw, NOT remote */
    TTP_MACTBL_LOCL (WHITE, mct->age && mct->vld && !mct->prm && !mct->gwf && !mct->rem,
                     WHITE "%27s  %4s %7s  %s\n", "Local Aging MAC addresses:",
                     "flag", "age(ms)", "tx-byts tx-pkts   rx-byts rx-pkts");

    /* local dead entries: invalid / dead entries */
    TTP_MACTBL_LOCL (BLUE, !mct->vld && !mct->gwf,
                     BLUE "%27s  %4s %7s  %s\n", "Local Dead MAC addresses:",
                     "flag", "age(ms)", "tx-byts tx-pkts   rx-byts rx-pkts");
#endif

    mutex_unlock (&ttp_mactbl_mutx);
    return sc;
}

static const struct kernel_param_ops ttp_param_mactbl_ops = {
    .set = ttp_param_dummy_set, /* not settable */
    .get = ttp_param_mactbl_get,
};

module_param_cb (mactbl, &ttp_param_mactbl_ops, &ttp_mactbl_ct, 0444);
MODULE_PARM_DESC (mactbl, "   read gateway mac-address table");


static int ttp_param_drop_pct_set (const char *val, const struct kernel_param *kp)
{
    int vv = 0;

    if ((0 != kstrtoint (val, 10, &vv)) || vv < 0 || vv > 10) {
        return -EINVAL;
    }

    return param_set_int (val, kp);
}

static const struct kernel_param_ops ttp_param_drop_pct_ops = {
    .set = ttp_param_drop_pct_set,
    .get = param_get_int,
};

module_param_cb (drop_pct, &ttp_param_drop_pct_ops, &ttp_drop_pct, 0644);
MODULE_PARM_DESC (drop_pct, " packet drop percent (default=(0), [0:10])");


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
MODULE_PARM_DESC (shutdown, " modttpoe shutdown state");


static int ttp_param_verbose_set (const char *val, const struct kernel_param *kp)
{
    int vv = 0;

    if ((0 != kstrtoint (val, 10, &vv)) || vv < 0 || vv > 3) {
        return -EINVAL;
    }
    return param_set_int (val, kp);
}

static const struct kernel_param_ops ttp_param_verbose_ops = {
    .set = ttp_param_verbose_set,
    .get = param_get_int,
};

module_param_cb (verbose, &ttp_param_verbose_ops, &ttp_verbose, 0644);
MODULE_PARM_DESC (verbose, "  kernel log verbosity level (default=(-1), 0, 1, 2, 3)");


static int ttp_nh4_mac_resolve (struct ttp_intf_cfg *zcfg)
{
    int rv = 0;
    struct flowi4 fl4;
    struct in_addr nh4;
    struct rtable *rt4;
    struct in_ifaddr *ifa4;
    struct neighbour *neigh;

    memset (&fl4, 0, sizeof fl4);
    fl4.daddr = zcfg->da4.s_addr;
    if (IS_ERR (rt4 = ip_route_output_key (&init_net, &fl4))) {
        TTP_LOG ("%s: Error: route lookup failed: ttp-gw:%pI4\n", __FUNCTION__,
                 &zcfg->da4);
        rv = -ENETUNREACH;
        goto end;
    }
    if ((rt4->dst.dev->flags & IFF_LOOPBACK) || (!(rt4->dst.dev->flags & IFF_UP))) {
        TTP_LOG ("%s: Error: dev lookup failed: %s is %s\n", __FUNCTION__,
                 rt4->dst.dev->name,
                 rt4->dst.dev->flags & IFF_LOOPBACK ? "LOOPBACK" : "!UP");
        rv = -ENODEV;
        goto end;
    }

    zcfg->dev = rt4->dst.dev;
    zcfg->gwy = !!rt4->rt_uses_gateway;
    nh4.s_addr = !zcfg->gwy ? zcfg->da4.s_addr : rt4->rt_gw4;
    if (!(neigh = dst_neigh_lookup (&rt4->dst, &nh4))) {
        TTP_LOG ("%s: Error: neighbor lookup failed: nh-ip4:%pI4\n", __FUNCTION__,
                 &nh4);
        rv = -EHOSTUNREACH;
        goto end;
    }

    memcpy (zcfg->mac, neigh->ha, ETH_ALEN);
    neigh_release (neigh);
    dst_release (&rt4->dst);

    if (is_valid_ether_addr (zcfg->mac)) {
        /* Iterate over ipv4 addrs on 'gw-dev' whose subnet == next-hop-ipv4
         * Set src-ipv4 of the v4-gw - used when sending gw-ctrl pkts to v4-gateways */
        rcu_read_lock ();
        for (ifa4 = rcu_dereference (zcfg->dev->ip_ptr->ifa_list); ifa4;
             ifa4 = rcu_dereference (ifa4->ifa_next)) {
            u32 mask = inet_make_mask (ifa4->ifa_prefixlen);
            if ((nh4.s_addr & mask) == (ifa4->ifa_address & mask)) {
                zcfg->sa4.s_addr = ifa4->ifa_address;
                break;
            }
        }
        rcu_read_unlock ();

        TTP_LOG ("  `->zn:%d gw:%pI4 -> mac:%*pM\n"
                 "    `->via:%s:%pI4 -> dev:%s\n",
                 zcfg->zon, &zcfg->da4, ETH_ALEN, zcfg->mac,
                 zcfg->gwy ? "rt-v4" : "dir-arp", &nh4, zcfg->dev->name);

        rv = 0;  /* success */
    }
    else {
        TTP_LOG ("`->nh-mac: %pI4 unresolved, re-try arp\n", &nh4);
        neigh_resolve_output (neigh, NULL);
        rv = EAGAIN;
    }

end:
    return rv;
}

#define DST2RT6(dst) container_of (dst, struct rt6_info, dst)

static int ttp_nh6_mac_resolve (struct ttp_intf_cfg *zcfg)
{
    int rv = 0;
    struct flowi6 fl6;
    struct in6_addr nh6;
    struct rt6_info *rt6;
    struct list_head *lhp;
    struct dst_entry *dst;
    struct neighbour *neigh;
    struct inet6_ifaddr *ifa6;

    memset (&fl6, 0, sizeof fl6);
    fl6.daddr = zcfg->da6;
    if (IS_ERR (dst = ip6_route_output_flags (&init_net, NULL, &fl6, 0))) {
        TTP_LOG ("%s: Error: route6 lookup failed: gw:%pI6c\n", __FUNCTION__,
                 &zcfg->da6);
        rv = -ENETUNREACH;
        goto end;
    }
    if ((dst->dev->flags & IFF_LOOPBACK) || (!(dst->dev->flags & IFF_UP))) {
        TTP_LOG ("%s: Error: dev lookup failed: %s is %s\n", __FUNCTION__,
                 dst->dev->name, dst->dev->flags & IFF_LOOPBACK ? "LOOPBACK" : "!UP");
        rv = -ENODEV;
        goto end;
    }

    zcfg->dev = dst->dev;
    rt6 = DST2RT6 (dst);
    zcfg->gwy = !!(rt6->rt6i_flags & RTF_GATEWAY);
    nh6 = !zcfg->gwy ? zcfg->da6 : rt6->rt6i_gateway;
    if (!(neigh = dst_neigh_lookup (&rt6->dst, &nh6))) {
        TTP_LOG ("%s: Error: neighbor lookup failed: nh-ip6:%pI6c\n", __FUNCTION__,
                 &nh6);
        rv = -EHOSTUNREACH;
        goto end;
    }

    memcpy (zcfg->mac, neigh->ha, ETH_ALEN);
    neigh_release (neigh);
    dst_release (&rt6->dst);

    if (is_valid_ether_addr (zcfg->mac)) {
        /* Iterate over ipv6 addrs on 'gw-dev' whose subnet == next-hop-ipv6
         * Set src-ipv6 of the v6-gw - used when sending gw-ctrl pkts to v6-gateways */
        rcu_read_lock ();
        list_for_each (lhp, &zcfg->dev->ip6_ptr->addr_list) {
            if (!(ifa6 = list_entry (lhp, struct inet6_ifaddr, if_list))) {
                break;
            }
            if (ipv6_prefix_equal (&nh6, &ifa6->addr, ifa6->prefix_len)) {
                zcfg->sa6 = ifa6->addr;
                break;
            }
        }
        rcu_read_unlock ();

        TTP_LOG ("  `->zn:%d gw:%pI6c -> mac:%*pM\n"
                 "    `->via:%s:%pI6c -> dev:%s\n",
                 zcfg->zon, &zcfg->da6, ETH_ALEN, zcfg->mac,
                 zcfg->gwy ? "rt-v6" : "dir-nd6", &nh6, zcfg->dev->name);

        rv = 0;  /* success */
    }
    else {
        TTP_LOG ("`->nh-mac: %pI6c unresolved, re-try nd6\n", &nh6);
        neigh_resolve_output (neigh, NULL);
        rv = EAGAIN;
    }

end:
    return rv;
}


static int ttp_nhmac_resolve (struct ttp_intf_cfg *zcfg)
{
    int rv = 0;

    if (is_valid_ether_addr (zcfg->mac)) {
        TTP_DBG ("%s: zn:%d has a valid gwmac:%*phC\n", __FUNCTION__,
                 zcfg->zon, ETH_ALEN, zcfg->mac);
        goto end;
    }
    if (zcfg->ver == 4) {
        rv = ttp_nh4_mac_resolve (zcfg);
    }
    else if (zcfg->ver == 6) {
        rv = ttp_nh6_mac_resolve (zcfg);
    }
    else {
        BUG_ON (1);
    }

end:
    return rv;
}


static int ttp_all_nhmacs_resolve (void)
{
    int zn;
    int ir, rv = 0;
    struct ttp_intf_cfg *zcfg;

    for (zn = 1; zn < TTP_MAX_NUM_ZONES; zn++) {
        if (ttp_myzone (zn)) { /* skip resolving nh to myself */
            continue;
        }
        if (!(zcfg = ttp_zcfg (zn))) {
            continue;
        }
        if (zcfg->ver != 4 && zcfg->ver != 6) {
            continue;
        }
        if (!(ir = ttp_nhmac_resolve (zcfg))) {
            continue;
        }
        if (EAGAIN == ir) {
            rv = EAGAIN;
            continue;
        }
        return ir; /* nhmac_resolve error */
    }
    return rv;
}


static void ttp_gw_local_mac_learn (const char *mac)
{
    int rv;

    if ((rv = ttp_mactbl_add (ttp_myzn, mac, TTP_GW_CTL_OP_LOCAL_ADD))) {
        if (rv != EEXIST) {
            TTP_LOG ("`-> Error: mac-table full (rv:%d)\n", rv);
            return;
        }
    }
    TTP_DB2 ("%s: gw_mac_adv: zn:%d  mac:%*phC%s\n", __FUNCTION__, ttp_myzn,
             ETH_ALEN, mac, rv == EEXIST ? "" : " (new)");
}


static void ttp_gw_ctl_send (const char *mac, enum ttp_mac_opcodes oc)
{
    int zn;
    u8 *op, *pkt;
    u16 frame_len, pkt_len;
    struct sk_buff *skb;
    struct ethhdr *eth;
    struct ttp_tsla_shim_hdr *tsh;
    struct ttp_intf_cfg *zcfg;

    if (!(oc == TTP_GW_CTL_OP_REMOTE_DEL ||
          oc == TTP_GW_CTL_OP_REMOTE_ADD ||
          oc == TTP_GW_CTL_OP_GATEWAY_ADD)) {
        return;
    }

    for (zn = 1; zn < TTP_MAX_NUM_ZONES; zn++) {
        if (ttp_myzone (zn)) { /* skip sending gw-ctrl to myself */
            continue;
        }
        if (!(zcfg = ttp_zcfg (zn))) {
            continue;
        }
        if (!zcfg->dev) {
            continue;
        }
        if (!is_valid_ether_addr (zcfg->mac)) {
            continue;
        }
        if (!(skb = ttpip_skb_aloc ())) {
            TTP_LOG ("%s: Error: send mac:%*phC -> zn:%d failed: ENOMEM\n",
                     __FUNCTION__, ETH_ALEN, mac, zn);
            return;
        }
        TTP_DB2 ("%s: send mac:%*phC -> zn:%d\n", __FUNCTION__, ETH_ALEN, mac, zn);

        eth = (struct ethhdr *)skb_mac_header (skb);
        pkt = (u8 *)(eth + 1);
        memcpy (eth->h_source, zcfg->dev->dev_addr, ETH_ALEN);
        memcpy (eth->h_dest, zcfg->mac, ETH_ALEN);

        /* Make canonical skb */
        skb_reset_mac_header (skb);
        skb_reset_network_header (skb);

        pkt_len = sizeof (struct ttp_tsla_shim_hdr) + 2; /* control pkt */
        tsh = NULL;
        if (zcfg->ver == 4) {
            skb->protocol = eth->h_proto = htons (ETH_P_IP);
            tsh = (struct ttp_tsla_shim_hdr *)ttp_prepare_ipv4 (pkt, pkt_len,
                                                                zcfg->sa4.s_addr,
                                                                zcfg->da4.s_addr, true);
            frame_len = ETH_HLEN + sizeof (struct iphdr) + pkt_len;
        }
        else if (zcfg->ver == 6) {
            skb->protocol = eth->h_proto = htons (ETH_P_IPV6);
            tsh = (struct ttp_tsla_shim_hdr *)ttp_prepare_ipv6 (pkt, pkt_len,
                                                                &zcfg->sa6, &zcfg->da6);
            frame_len = ETH_HLEN + sizeof (struct ipv6hdr) + pkt_len;
        }
        if (!tsh) {
            kfree_skb (skb);
            continue;
        }

        memset (tsh, 0, sizeof (*tsh));
        memmove (tsh->src_node, mac, ETH_ALEN/2);
        memmove (tsh->dst_node, &mac[3], ETH_ALEN/2);

        tsh->length = htons (2); /* control pkt */
        op = (u8 *)(tsh + 1);
        op[0] = oc;
        op[1] = ttp_myzn;
        if (ttp_verbose > 2) {
            ttp_print_shim_hdr (tsh);
        }

        skb->dev = (struct net_device *)zcfg->dev; /* forward to gateway */
        if (ttp_verbose > 2) {
            ttpip_pretty_print_data ("raw:", true, skb->dev->name,
                                     (u8 *)eth, skb->len, 0);
        }
        TTP_DB2 ("<<- Tx packet: (gw-ctrl) len:%d dev:%s\n", skb->len, skb->dev->name);

        skb_trim (skb, max (frame_len, TTP_MIN_FRAME_LEN));
        skb_reset_network_header (skb);
        skb_reset_mac_header (skb);
        dev_queue_xmit (skb);
    }
}


/* Decode shim header, validate ctrl-params, get [oc, zn] info from payload, and
 * learn the mac-address (remote and gateway) into our mactbl - based on [oc, zn] */
static void ttp_gw_ctl_recv (const char *mac, const struct ttp_tsla_shim_hdr *tsh)
{
    u8 *op;
    int rv, zn;
    enum ttp_mac_opcodes oc;

    if (ttp_verbose > 2) {
        ttp_print_shim_hdr (tsh);
    }
    op = (u8 *)(tsh + 1);
    oc = op[0]; /* ctrl pkt op-code */
    zn = op[1]; /* remote gw zone */

    if (!ttp_zone_valid (zn)) {
        rv = ttp_mactbl_del (zn, mac, TTP_GW_CTL_OP_REMOTE_DEL);
        if (rv) {
            TTP_DB2 ("%s: Del %smac:%*phC from zone:%d\n", __FUNCTION__,
                     oc == TTP_GW_CTL_OP_REMOTE_DEL ? "remote" : "gw", ETH_ALEN, mac, zn);
        }
        return;
    }

    switch ((oc)) {
    case TTP_GW_CTL_OP_REMOTE_DEL:
        rv = ttp_mactbl_del (zn, mac, TTP_GW_CTL_OP_REMOTE_DEL);
        if (rv) {
            TTP_DB2 ("%s: Del %smac:%*phC from zone:%d\n", __FUNCTION__,
                     oc == TTP_GW_CTL_OP_REMOTE_DEL ? "remote" : "gw", ETH_ALEN, mac, zn);
        }
        break;
    case TTP_GW_CTL_OP_REMOTE_ADD:
    case TTP_GW_CTL_OP_GATEWAY_ADD:
        if ((rv = ttp_mactbl_add (zn, mac, oc))) {
            if (rv != EEXIST) {
                TTP_LOG ("`-> Error: mac-table full (rv:%d)\n", rv);
            }
        }
        TTP_DB2 ("%s: Add %smac:%*phC from zone:%d\n", __FUNCTION__,
                 oc == TTP_GW_CTL_OP_REMOTE_ADD ? "" : "gw-", ETH_ALEN, mac, zn);
        break;
    default:
        TTP_LOG ("%s: Invalid op(%d) mac:%*phC from zone %d\n",
                 __FUNCTION__, oc, ETH_ALEN, mac, zn);
        return;
    }
}


static void ttp_nh_mac_tmr_cb (struct timer_list *tl)
{
    struct ttp_timer *tm;
    int rv, to;

    if (ttp_shutdown) {
        return;
    }
    if (!(tm = from_timer (tm, tl, tmh))) {
        return;
    }
    if (tm->rst) {
        tm->rst = false;
        tm->try = 0;
    }
    if (tm->try >= tm->max) {
        if (tm->try == tm->max) {
            TTP_LOG ("Error: failed nh lookup (tm->try:%d); start slow scan\n", tm->try);
        }
        tm->try = tm->max + 1;
        to = msecs_to_jiffies (ttp_gw_ctl_tmr.exp);
        mod_timer (&ttp_nh_mac_tmr.tmh, jiffies + (to * 50)); /* 50x slower */
    }
    else if ((rv = ttp_all_nhmacs_resolve ()) < 0) {
        TTP_LOG ("Error: route/neighbor lookup failed\n");
    }
    else if (0 == rv) {
        TTP_LOG ("%s: resolved all nh-macs\n", __FUNCTION__);
    }
    else if (EAGAIN == rv) {
        to = msecs_to_jiffies (ttp_gw_ctl_tmr.exp);
        to *= (!tm->try++ ? 1 : 4); /* 2nd, 3rd,.. retry delayed 4x */
        mod_timer (&ttp_nh_mac_tmr.tmh, jiffies + to);
        TTP_LOG ("%s: re-try(#%d): nh-macs\n", __FUNCTION__, tm->try);
    }
}


static void ttp_gw_ctl_tmr_cb (struct timer_list *tl)
{
    u8 *op;
    struct ttp_timer *tm;
    struct sk_buff *skb;
    struct ethhdr *eth;
    struct ttp_tsla_type_hdr *tth;
    struct ttp_tsla_shim_hdr *tsh;
    struct ttp_mactable *mct = NULL;

    if (!(tm = from_timer (tm, tl, tmh))) {
        return;
    }
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
    ttpip_mcast_mac_create (eth->h_dest);

    eth->h_proto = htons (TESLA_ETH_P_TTPOE);
    tth = (struct ttp_tsla_type_hdr *)(eth + 1);
    tsh = (struct ttp_tsla_shim_hdr *)ttp_prepare_tth ((u8 *)tth, 0, true);

    memset (tsh, 0, sizeof (*tsh));
    memmove (tsh->src_node, eth->h_source, ETH_ALEN/2);
    memmove (tsh->dst_node, &eth->h_source[3], ETH_ALEN/2);

    tsh->length = htons (2); /* control pkt */
    op = (u8 *)(tsh + 1);
    op[0] = 2; /* == OPEN_NACK */
    op[1] = ttp_myzn;
    if (ttp_verbose > 2) {
        ttp_print_shim_hdr (tsh);
    }

    skb->dev = ttpip_etype_tsla.dev; /* forward frame to ttp-nodes within zone */
    skb->protocol = eth->h_proto;
    if (ttp_verbose > 2) {
        ttpip_pretty_print_data ("raw:", true, skb->dev->name, (u8 *)eth, skb->len, 0);
    }
    TTP_DB2 ("<<- Tx packet: (gw-mac-adv) len:%d dev:%s\n", skb->len, skb->dev->name);

    skb_reset_network_header (skb);
    skb_reset_mac_header (skb);
    dev_queue_xmit (skb);

    /* Walk mactbl, send node-macs learned / aged in my zone to remote gws */
    while ((mct = ttp_mactbl_rbtree_find_next (mct))) {
        if (!mct->vld || mct->prm) {
            continue;
        }
        if (mct->age >= TTP_MAC_AGEOUT_OLD) {
            if (!mct->rem) {
                /* reached OLD threshold - withdraw local MAC */
                ttp_gw_ctl_send (mct->mac, TTP_GW_CTL_OP_REMOTE_DEL);
            }
            if (mct->age >= TTP_MAC_AGEOUT_MAX) {
                /* Reached Max threshold - we're not deleting local mac-entries,
                 * Only invalidating the entry */
                mct->vld = 0; /* Can resurrect later when mac-address seen agtain */
                continue;
            }
        }
        mct->age++;
    }

    /* Finally send my gw-mac to remote gws */
    ttp_gw_ctl_send ((char *)ttpip_etype_tsla.dev->dev_addr, TTP_GW_CTL_OP_GATEWAY_ADD);

end:
    if (!ttp_shutdown) { /* run timer only if enabled */
        mod_timer (&ttp_gw_ctl_tmr.tmh, jiffies + msecs_to_jiffies (ttp_gw_ctl_tmr.exp));
    }
}


static int ttpip_frm_recv (struct sk_buff *skb, struct net_device *dev,
                           struct packet_type *ptype, struct net_device *odev)
{
    int zs = 0, zt = 0;
    u16 frame_len, pkt_len, rx_byt;
    struct ttp_tsla_type_hdr *tth;
    struct ttp_tsla_shim_hdr *tsh;
    struct ttp_intf_cfg *zcfg;
    struct ethhdr *eth, leh = {0};
    struct ttp_mactable *mcs, *mct;

    if (ttp_shutdown) {
        TTP_LOG ("%s: ->> Rx frame dropped: ttp-gw is shutdown\n", __FUNCTION__);
        goto end;
    }
    if ((skb->len > TTP_MAX_FRAME_LEN) || (ntohs (skb->protocol) != TESLA_ETH_P_TTPOE)) {
        goto end; /* drop silently */
    }
    if (ttp_rnd_flip (ttp_drop_pct)) {
        TTP_LOG ("%s: ->! Rx frame dropped: rate:%d%%\n", __FUNCTION__, ttp_drop_pct);
        goto end;
    }

    rx_byt = skb->len; /* save rx-len to update stats once drop decisions are complete */
    eth = (struct ethhdr *)skb_mac_header (skb);
    if (!ether_addr_equal (ttpip_etype_tsla.dev->dev_addr, eth->h_dest)) {
        goto end; /* drop silently */
    }
    if (skb_headroom (skb) < TTP_IP_HEADROOM) {
        if (pskb_expand_head (skb, TTP_IP_HEADROOM, 0, GFP_ATOMIC)) {
            TTP_LOG ("%s: Drop frame: insufficient headroom\n", __FUNCTION__);
            goto end;
        }
    }
    TTP_DBG ("%s: ->> Rx frame: len:%d dev:%s\n", __FUNCTION__, skb->len, skb->dev->name);

    tth = (struct ttp_tsla_type_hdr *)(eth + 1);
    if (tth->tthl != TTP_PROTO_TTHL) {
        TTP_LOG ("%s: Drop frame: Incorrect TTHL: (%d)\n", __FUNCTION__, tth->tthl);
        goto end;
    }
    if (!tth->gway) {
        TTP_LOG ("%s: Drop frame: Improper ingress gw frame: 'gw' flag not set in tth\n",
                 __FUNCTION__);
        goto end;
    }
    tsh = (struct ttp_tsla_shim_hdr *)(tth + 1);

    /* Decode shim src/dst_node fields */
    ttp_prepare_mac_with_oui (leh.h_dest, Tesla_Mac_Oui, tsh->dst_node);
    ttp_prepare_mac_with_oui (leh.h_source, Tesla_Mac_Oui, tsh->src_node);

    if (ttp_verbose > 1) {
        if ((is_valid_ether_addr (leh.h_source) && is_valid_ether_addr (leh.h_dest) &&
             ttp_verbose > 1) || ttp_verbose > 2) {
            ttp_print_tsla_type_hdr (tth);
            ttp_print_shim_hdr (tsh);
        }
    }

    /* local-mac learn */
    ttp_gw_local_mac_learn (eth->h_source);

    if (!(mcs = ttp_mactbl_find (leh.h_source))) { /* Lookup src-mac */
        if ((is_valid_ether_addr (leh.h_source) && ttp_verbose > 1) || ttp_verbose > 2) {
            TTP_LOG ("%s: Drop frame: No src-mac:%*phC\n", __FUNCTION__,
                     ETH_ALEN, leh.h_source);
        }
        goto end;
    }
    if (!(zs = mcs->zon)) {
        TTP_LOG ("%s: Drop frame: Invalid src-zone\n", __FUNCTION__);
        goto end;
    }
    if (!(mct = ttp_mactbl_find (leh.h_dest))) { /* Lookup dst-mac */
        if ((is_valid_ether_addr (leh.h_dest) && ttp_verbose > 1) || ttp_verbose > 2) {
            TTP_LOG ("%s: Drop frame: No dst-mac:%*phC\n", __FUNCTION__,
                     ETH_ALEN, leh.h_dest);
        }
        goto end;
    }
    if (!(zt = mct->zon)) {
        TTP_LOG ("%s: Drop frame: Invalid tgt-zone\n", __FUNCTION__);
        goto end;
    }
    if (zs == zt) {
        TTP_LOG ("%s: Drop frame: src-zone == dst-zone(%d)\n", __FUNCTION__, zs);
        goto end;
    }
    if (!(zcfg = ttp_zcfg (zt))) {
        TTP_LOG ("%s: Drop frame: error getting zone config from tgt-zone(%d)\n",
                 __FUNCTION__, zt);
        goto end;
    }
    if (!is_valid_ether_addr (zcfg->mac)) {
        TTP_LOG ("`->Invalid gw-mac:%*pM, Drop frame: len:%d dev:%s\n",
                 ETH_ALEN, zcfg->mac, skb->len, skb->dev->name);
        ttp_nhmac_resolve (zcfg); /* trigger arp, no timers are kicked off */
        goto end;
    }

    if (ttp_verbose > 1) {
        ttpip_pretty_print_data ("raw:", false, skb->dev->name, (u8 *)eth, skb->len,
                                 (skb->len > TTP_MAX_FRAME_LEN) ? 96 : 0);
    }
    TTP_DB1 ("%s: found src-mac:%*phC src-zone:%d\n", __FUNCTION__,
             ETH_ALEN, mcs->mac, mcs->zon);
    TTP_DB1 ("%s: found dst-mac:%*phC tgt-zone:%d\n", __FUNCTION__,
             ETH_ALEN, mct->mac, mct->zon);
    TTP_DBG ("->> Ingress gw: ttp->ipv%d zn:%d->%d len:%d dev:%s\n",
             zcfg->ver, zs, zt, skb->len, skb->dev->name);
    if (ntohs (eth->h_proto) == ETH_P_IPV6) {
        TTP_LOG ("%s: Drop frame: EthType:0x%04x == IPv6 (late)\n", __FUNCTION__,
                 ntohs (eth->h_proto));
        goto end;
    }

    /* Make canonical skb */
    skb_reset_mac_header (skb);
    skb_reset_network_header (skb);

    skb_pull (skb, (tth->tthl * 4)); /* strip tesla-type header */

    pkt_len = ntohs (tsh->length); /* incoming len in shim header */
    tsh = NULL;
    if (zcfg->ver == 4) {
        skb_push (skb, sizeof (struct iphdr)); /* add gw-IPv4 header */
        skb->protocol = htons (ETH_P_IP);
        tsh = (struct ttp_tsla_shim_hdr *)ttp_prepare_ipv4 (skb->data, pkt_len,
                                                            zcfg->sa4.s_addr,
                                                            zcfg->da4.s_addr, true);
        frame_len = ETH_HLEN + sizeof (struct iphdr) + pkt_len;
    }
    else if (zcfg->ver == 6) {
        skb_push (skb, sizeof (struct ipv6hdr)); /* add gw-IPv6 header */
        skb->protocol = htons (ETH_P_IPV6);
        tsh = (struct ttp_tsla_shim_hdr *)ttp_prepare_ipv6 (skb->data, pkt_len,
                                                            &zcfg->sa6, &zcfg->da6);
        frame_len = ETH_HLEN + sizeof (struct ipv6hdr) + pkt_len;
    }
    else {
        BUG_ON (1);
    }
    if (!tsh) { /* prepare_ippkt failed */
        goto end; /* drop silently */
    }

    /* update stats */
    mcs->r.frm++;
    mcs->r.byt += rx_byt;
    mct->t.frm++;
    mct->t.byt += skb->len;

    skb_push (skb, ETH_HLEN); /* add ethernet header */
    eth = (struct ethhdr *)skb->data;
    memcpy (eth->h_source, zcfg->dev->dev_addr, ETH_ALEN);
    memcpy (eth->h_dest, zcfg->mac, ETH_ALEN);
    eth->h_proto = skb->protocol;

    skb->dev = (struct net_device *)zcfg->dev; /* forward to gateway */
    skb_trim (skb, max (frame_len, TTP_MIN_FRAME_LEN));
    skb_reset_network_header (skb);
    skb_reset_mac_header (skb);

    if (ttp_verbose > 1) {
        ttpip_pretty_print_data ("raw:", true, skb->dev->name, (u8 *)eth, skb->len, 0);
    }
    TTP_DBG ("<<- Tx packet: (ttp-gw) len:%d dev:%s\n", skb->len, skb->dev->name);

    dev_queue_xmit (skb);
    return 0;

end:
    kfree_skb (skb);
    return 0;
}


static int ttpip_pkt_recv (struct sk_buff *skb, struct net_device *dev,
                           struct packet_type *ptype, struct net_device *odev)
{
    int zs, zt, ver;
    u16 tot_len, rx_byt;
    struct iphdr *ipv4;
    struct ipv6hdr *ipv6;
    struct ttp_tsla_type_hdr *tth;
    struct ttp_tsla_shim_hdr *tsh;
    struct ethhdr *eth, leh = {0};
    struct ttp_intf_cfg *myzcfg;
    struct ttp_mactable *mcs, *mct;

    if (ttp_shutdown) {
        TTP_LOG ("%s: ->> Rx pkt dropped: ttp-gw is shutdown\n", __FUNCTION__);
        goto end;
    }
    if (!(myzcfg = ttp_myzcfg ())) {
        TTP_LOG ("%s: Error: my own zone lookup failed\n", __FUNCTION__);
        goto end;
    }
    if (skb->len > TTP_MAX_FRAME_LEN) {
        goto end; /* drop silently */
    }
    if (ttp_rnd_flip (ttp_drop_pct)) {
        TTP_LOG ("%s: ->! Rx pkt dropped: rate:%d%%\n", __FUNCTION__, ttp_drop_pct);
        goto end;
    }

    rx_byt = skb->len; /* save rx-len to update stats once drop decisions are complete */
    eth = (struct ethhdr *)skb_mac_header (skb);
    if (eth->h_proto == htons (ETH_P_IP)) {
        ver = 4;
        ipv4 = (struct iphdr *)skb_network_header (skb); /* skb_network_header */
        if (TTP_IPPROTO_TTP != ipv4->protocol || ipv4->daddr != myzcfg->da4.s_addr) {
            goto end; /* drop silently */
        }
    }
    else if (eth->h_proto == htons (ETH_P_IPV6)) {
        ver = 6;
        ipv6 = (struct ipv6hdr *)skb_network_header (skb);
        if (TTP_IPPROTO_TTP != ipv6->nexthdr || ipv6_addr_cmp (&ipv6->daddr,
                                                               &myzcfg->da6)) {
            goto end; /* drop silently */
        }
    }
    else {
        goto end; /* drop silently */
    }
    if (skb_headroom (skb) < TTP_IP_HEADROOM) {
        if (pskb_expand_head (skb, TTP_IP_HEADROOM, 0, GFP_ATOMIC)) {
            TTP_LOG ("%s: Drop pkt: insufficient headroom\n", __FUNCTION__);
            goto end;
        }
    }

    /* Make canonical skb */
    skb_reset_mac_header (skb);
    skb_reset_network_header (skb);

    /* Decap IP to extract tsh - handle ipv4 or ipv6 */
    if (ver == 4) {
        if (ttp_verbose > 2) {
            ttp_print_ipv4_hdr (ipv4);
        }
        tsh = (struct ttp_tsla_shim_hdr *)(ipv4 + 1);
        tot_len = ntohs (ipv4->tot_len);

        skb_pull (skb, (ipv4->ihl * 4)); /* strip IPv4 header */
    }
    else if (ver == 6) {
        if (ttp_verbose > 2) {
            ttp_print_ipv6_hdr (ipv6);
        }
        tsh = (struct ttp_tsla_shim_hdr *)(ipv6 + 1);
        tot_len = ntohs (ipv6->payload_len) + sizeof (struct ipv6hdr);

        skb_pull (skb, sizeof (struct ipv6hdr)); /* strip IPv6 header */
    }
    else {
        goto end; /* drop silently */
    }
    if (tsh->length == htons (2)) { /* tsh length == 2 => control packet */
        TTP_DB2 ("%s: ->> Rx (gw-ctrl) pkt: len:%d dev:%s\n", __FUNCTION__,
                 skb->len, skb->dev->name);
        ttpip_pretty_print_data ("raw:", false, skb->dev->name, (u8 *)eth, skb->len,
                                 (skb->len > TTP_MAX_FRAME_LEN) ? 96 : 0);

        memmove (leh.h_dest, tsh->src_node, ETH_ALEN/2);
        memmove (&leh.h_dest[3], tsh->dst_node, ETH_ALEN/2);
        ttp_gw_ctl_recv (leh.h_dest, tsh);
        goto end; /* consume packet */
    }
    TTP_DBG ("%s: ->> Rx pkt: len:%d dev:%s\n", __FUNCTION__, skb->len, skb->dev->name);
    if (ttp_verbose) {
        ttpip_pretty_print_data ("raw:", false, skb->dev->name, (u8 *)eth, skb->len,
                                 (skb->len > TTP_MAX_FRAME_LEN) ? 96 : 0);
    }

    /* Decode shim src/dst_node fields */
    ttp_prepare_mac_with_oui (leh.h_dest, Tesla_Mac_Oui, tsh->dst_node);
    ttp_prepare_mac_with_oui (leh.h_source, Tesla_Mac_Oui, tsh->src_node);

    /* Prepare TTPoE frame to forward to destination ttp-node */
    skb_push (skb, sizeof (struct ttp_tsla_type_hdr)); /* add tesla-type header */

    tth = (struct ttp_tsla_type_hdr *)skb->data;
    ttp_prepare_tth (skb->data, skb->len, true);

    ttp_print_eth_hdr (eth);
    ttp_print_tsla_type_hdr (tth);
    ttp_print_shim_hdr (tsh);

    skb_push (skb, ETH_HLEN); /* add ethernet header */
    eth = (struct ethhdr *)skb->data;
    memcpy (eth->h_source, ttpip_etype_tsla.dev->dev_addr, ETH_ALEN);
    memcpy (eth->h_dest, leh.h_dest, ETH_ALEN);
    eth->h_proto = htons (TESLA_ETH_P_TTPOE);

    skb_trim (skb, max ((u16)(tot_len + ETH_HLEN), TTP_MIN_FRAME_LEN));
    skb->len = max ((u16)skb->len, TTP_MIN_FRAME_LEN);

    /* Lookup src-mac addr in mactbl */
    if ((mcs = ttp_mactbl_find (leh.h_source))) {
        TTP_DB2 ("%s: found src-mac:%*phC zn:%d\n", __FUNCTION__,
                 ETH_ALEN, mcs->mac, mcs->zon);
        zs = mcs->zon;
    }
    /* Lookup dst-mac addr in mactbl */
    if ((mct = ttp_mactbl_find (leh.h_dest))) {
        TTP_DB2 ("%s: found dst-mac:%*phC zn:%d\n", __FUNCTION__,
                 ETH_ALEN, mct->mac, mct->zon);
        zt = mct->zon;
    }
    if (!zs || !zt) {
        TTP_LOG ("%s: Drop frame: Invalid src-node (%d) and/or dst-node (%d)\n",
                 __FUNCTION__, zs, zt);
        goto end;
    }
    if (zs == zt) {
        TTP_LOG ("%s: Drop pkt: src-node and dst-node are in same zone (%d)\n",
                 __FUNCTION__, zs);
        goto end;
    }
    TTP_DBG ("<<-- Egress gw: ttp<-ipv%d zn:%d<-%d len:%d dev:%s\n",
             ver, zt, zs, skb->len, skb->dev->name);

    /* update stats */
    mcs->r.frm++;
    mcs->r.byt += rx_byt;
    mct->t.frm++;
    mct->t.byt += skb->len;

    skb->dev = ttpip_etype_tsla.dev; /* forward frame to ttp-nodes within zone */
    skb->protocol = eth->h_proto;
    ttpip_pretty_print_data ("raw:", true, skb->dev->name, (u8 *)eth, skb->len, 0);
    TTP_DBG ("<<- Tx frame: len:%d dev:%s\n", skb->len, skb->dev->name);

    skb_reset_network_header (skb);
    skb_reset_mac_header (skb);
    dev_queue_xmit (skb);
    return 0;

end:
    kfree_skb (skb);
    return 0;
}


static int __init ttpip_init (void)
{
    int rv;
    struct ttp_intf_cfg *myzcfg;

    if (!ttp_num_gwips) {
        TTP_LOG ("Error: no gwips specified - unloading\n");
        rv = -ENODEV;
        goto error;
    }
    if (!ttp_dev || (!(ttpip_etype_tsla.dev = dev_get_by_name (&init_net, ttp_dev)))) {
        TTP_LOG ("Error: Not found dev(%s) - unloading\n", ttp_dev ?: "<unspecified>");
        rv = -ENODEV;
        goto error;
    }
    dev_put (ttpip_etype_tsla.dev);
    if (!(ttpip_etype_tsla.dev->flags & IFF_UP)) {
        TTP_LOG ("Error: Device dev (%s) is DOWN - unloading\n", ttp_dev);
        rv = -ENETDOWN;
        goto error;
    }
    if (!ttp_zone_valid (ttp_myzn)) {
        TTP_LOG ("Error: zone: not known - unloading\n");
        rv = -EINVAL;
        goto error;
    }
    if (!(myzcfg = ttp_myzcfg ())) {
        TTP_LOG ("Error: No zone-config for my-zone(%d) - unloading\n", ttp_myzn);
        rv = -ENODEV;
        goto error;
    }
    if (!myzcfg->dev) {
        TTP_LOG ("Error: No layer3 interface for my-zone - unloading\n");
        rv = -ENODEV;
        goto error;
    }
    if ((rv = ttp_mactbl_add (ttp_myzn, ttpip_etype_tsla.dev->dev_addr,
                              TTP_GW_CTL_OP_GATEWAY_SLF))) {
        if (rv != EEXIST) {
            TTP_LOG ("`-> Error: mac-table full (rv:%d) - unloading\n", rv);
            goto error;
        }
    }

    TTP_LOG ("%s: ip%d-if:'%s' mac:%*pM\n"
             "            ttp-if:'%s' mac:%*pM\n", __FUNCTION__, myzcfg->ver,
             myzcfg->dev->name, ETH_ALEN, myzcfg->dev->dev_addr,
             ttpip_etype_tsla.dev->name, ETH_ALEN, ttpip_etype_tsla.dev->dev_addr);

    /* initialize and start the timers */
    timer_setup (&ttp_nh_mac_tmr.tmh, &ttp_nh_mac_tmr_cb, 0);
    timer_setup (&ttp_gw_ctl_tmr.tmh, &ttp_gw_ctl_tmr_cb, 0);

    mod_timer (&ttp_nh_mac_tmr.tmh, jiffies + msecs_to_jiffies (100));
    mod_timer (&ttp_gw_ctl_tmr.tmh, jiffies + msecs_to_jiffies (100));

    mutex_init (&ttp_mactbl_mutx);
    mutex_init (&ttp_zoncfg_mutx);

    dev_add_pack (&ttpip_etype_tsla);
    dev_add_pack (&ttpip_etype_lyr3);
    TTP_LOG ("------------------ Module modttpip.ko loaded -----------------+\n");
    ttp_shutdown = 0;           /* enable for business */
    return 0;
error:
    TTP_LOG ("~~~~~~~~~~~~~~~~ Module modttpip.ko not loaded ~~~~~~~~~~~~~~~+\n");
    return rv;
}


static void __exit ttpip_exit (void)
{
    del_timer (&ttp_gw_ctl_tmr.tmh);
    del_timer (&ttp_nh_mac_tmr.tmh);
    dev_remove_pack (&ttpip_etype_tsla);
    dev_remove_pack (&ttpip_etype_lyr3);
    TTP_LOG ("~~~~~~~~~~~~~~~~~ Module modttpip.ko unloaded ~~~~~~~~~~~~~~~~+\n");
}


module_init (ttpip_init);
module_exit (ttpip_exit);

MODULE_AUTHOR ("dntundlam@tesla.com");
MODULE_DESCRIPTION ("TTP IP Gateway");
MODULE_VERSION ("1.0");
MODULE_LICENSE ("GPL");
