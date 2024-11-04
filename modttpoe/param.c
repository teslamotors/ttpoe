// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Tesla Inc. All rights reserved.
 *
 * TTP (TTPoE) A reference implementation of Tesla Transport Protocol (TTP) that runs
 *             directly over Ethernet Layer-2 Network. This is implemented as a Loadable
 *             Kernel Module that establishes a TTP-peer connection with another instance
 *             of the same module running on another Linux machine on the same Layer-2
 *             network. Since TTP runs over Ethernet, it is often referred to as TTP Over
 *             Ethernet (TTPoE).
 *
 *             The Protocol is specified to work at high bandwidths over 100Gbps and is
 *             mainly designed to be implemented in Hardware as part of Tesla's DOJO
 *             project.
 *
 *             This public release of the TTP software implementation is aligned with the
 *             patent disclosure and public release of the main TTP Protocol
 *             specification. Users of this software module must take into consideration
 *             those disclosures in addition to the license agreement mentioned here.
 *
 * Authors:    Diwakar Tundlam <dntundlam@tesla.com>
 *             Bill Chang <wichang@tesla.com>
 *             Spencer Sharkey <spsharkey@tesla.com>
 *
 * TTP-Spec:   Eric Quinnell <equinnell@tesla.com>
 *             Doug Williams <dougwilliams@tesla.com>
 *             Christopher Hsiong <chsiong@tesla.com>
 *
 * Version:    08/26/2022 wichang@tesla.com, "Initial version"
 *             02/09/2023 spsharkey@tesla.com, "add ttpoe header parser + test"
 *             05/11/2023 dntundlam@tesla.com, "ttpoe layers - nwk, transport, payload"
 *             07/11/2023 dntundlam@tesla.com, "functional state-machine, added tests"
 *             09/29/2023 dntundlam@tesla.com, "final touches"
 *             09/10/2024 dntundlam@tesla.com, "sync with TTP_Opcodes.pdf [rev 1.5]"
 *
 * This software is licensed under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation, and may be copied, distributed, and
 * modified under those terms.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; Without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE. See the GNU General Public License for more details.
 */

#ifndef MODULE
#define MODULE
#endif

#ifndef __KERNEL__
#define __KERNEL__
#endif

#include <linux/ctype.h>
#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/etherdevice.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/inet.h>
#include <linux/types.h>
#include <linux/bitops.h>
#include <linux/cred.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <net/addrconf.h>

#include <ttp.h>

#include "ttpoe.h"
#include "fsm.h"
#include "tags.h"
#include "noc.h"
#include "print.h"

u8 ttp_nhmac[ETH_ALEN];


TTP_UNUSED
static int ttp_param_dummy_set (const char *val, const struct kernel_param *kp)
{
    TTP_LOG ("%s: Error: kernel param not settable\n", __FUNCTION__);
    return -EPERM;
}

static const struct kernel_param_ops ttp_param_dev_ops = {
    .set = param_set_charp,
    .get = param_get_charp,
};

/* read-only parameter; must be set at module-load */
module_param_cb (dev, &ttp_param_dev_ops, &ttp_dev, 0444);
MODULE_PARM_DESC (dev, "      ttp device name (required at module-load)");


static int ttp_debug_target_enable (u64 *kid, struct ttpoe_host_info *tg)
{
    int rv;

    if (ttp_ipv4_encap && !ttp_ipv4_prefix) {
        TTP_LOG ("%s: Error: ttp ipv4-encap required to enable target\n", __FUNCTION__);
        return -EINVAL;
    }
    if ((rv = ttpoe_noc_debug_tgt (kid, tg))) {
        return rv;
    }
    if (ttp_verbose > 1) {
        if (ttp_ipv4_encap) {
            TTP_LOG ("%s: noc_debug: target.ip:%pI4 vc:%d gw:%d\n", __FUNCTION__,
                     &tg->ipa, tg->vc, tg->gw);
        }
        else {
            TTP_LOG ("%s: noc_debug: target.mac:%*phC vc:%d gw:%d\n", __FUNCTION__,
                     ETH_ALEN, tg->mac, tg->vc, tg->gw);
        }
    }
    return ttpoe_noc_debug_tx (NULL, NULL, 0, TTP_EV__TXQ__TTP_OPEN, &ttp_debug_target);
}

static int ttp_param_target_mac_set (const char *val, const struct kernel_param *kp)
{
    int rv = 0;
    u8  mac[ETH_ALEN];

    if (ttp_ipv4_encap && !ttp_ipv4_prefix) {
        TTP_LOG ("%s: Error: ttp ipv4-encap required to set dest-mac\n", __FUNCTION__);
        return -EINVAL;
    }
    for (rv = 0; rv < ETH_ALEN; rv++) {
        mac[rv] = simple_strtol (val, NULL, 16) & 0xff;
        val += 2;
        if (rv < (ETH_ALEN - 1) && (*val != ':')) {
            return -EINVAL;
        }
        if ((rv == (ETH_ALEN - 1) && (*val != '\n' && *val != '\0'))) {
            return -EINVAL;
        }
        val++;
    }

    if (!is_valid_ether_addr (mac)) {
        return -EADDRNOTAVAIL;
    }
    if (ether_addr_equal (ttp_debug_source.mac, mac)) {
        return -EADDRINUSE;
    }
    if (!ether_addr_equal (ttp_debug_target.mac, mac)) {
        ttp_debug_target.ve = 0;
        ether_addr_copy (ttp_debug_target.mac, mac);
    }
    return 0;
}

static int ttp_param_target_mac_get (char *buf, const struct kernel_param *kp)
{
    return snprintf (buf, 300, "%*phC\n", ETH_ALEN, ttp_debug_target.mac);
}

static const struct kernel_param_ops ttp_param_target_mac_ops = {
    .set = ttp_param_target_mac_set,
    .get = ttp_param_target_mac_get,
};

module_param_cb (dest_mac, &ttp_param_target_mac_ops, NULL, 0644);
MODULE_PARM_DESC (dest_mac, " ttp destination mac-address: "
                  "e.g. dest_mac=xx:xx:xx:xx:xx:xx)");


static int ttp_param_target_ve_set (const char *val, const struct kernel_param *kp)
{
    u64 kid;
    int rv = 0;

    if ((0 != kstrtoint (val, 10, &rv)) || rv < 0 || rv > 1) {
        return -EINVAL;
    }

    if (rv == ttp_debug_target.ve) {
        return 0;
    }

    ttp_debug_target.ve = rv;
    if (!ttp_debug_target.ve) {
        return 0; /* turning off valid - no checks needed */
    }

    if ((rv = ttp_debug_target_enable (&kid, &ttp_debug_target))) {
        ttp_debug_target.ve = 0; /* enable failed */
        return rv;
    }

    return 0;
}

static int ttp_param_target_ve_get (char *buf, const struct kernel_param *kp)
{
    return snprintf (buf, 300, "%d\n", ttp_debug_target.ve);
}

static const struct kernel_param_ops ttp_param_target_ve_ops = {
    .set = ttp_param_target_ve_set,
    .get = ttp_param_target_ve_get,
};

module_param_cb (valid, &ttp_param_target_ve_ops, NULL, 0644);
MODULE_PARM_DESC (valid, "    target is valid (default=0, or 1)");


static int ttp_param_vci_set (const char *val, const struct kernel_param *kp)
{
    int rv;
    u32 vci;

    val = strim ((char *)val);
    if ((rv = kstrtouint (val, 10, &vci))) {
        TTP_LOG ("%s: Error: Invalid vc-id format:'%s'\n", __FUNCTION__, val);
        return rv;
    }

    if (!TTP_VC_ID__IS_VALID (vci)) {
        return -ERANGE;
    }

    ttp_debug_target.vc = vci;

    return 0;
}

static int ttp_param_vci_get (char *buf, const struct kernel_param *kp)
{
    return snprintf (buf, 300, "%d\n", ttp_debug_target.vc);
}

static const struct kernel_param_ops ttp_param_vci_ops = {
    .set = ttp_param_vci_set,
    .get = ttp_param_vci_get,
};

module_param_cb (vci, &ttp_param_vci_ops, NULL, 0644);
MODULE_PARM_DESC (vci, "      ttp conn-VCI (default=0, 1, 2)");


static int ttp_param_target_use_gw_set (const char *val, const struct kernel_param *kp)
{
    int vv = 0;

    if ((0 != kstrtoint (val, 10, &vv)) || vv < 0 || vv > 1) {
        return -EINVAL;
    }

    if (ttp_debug_target.gw == vv) {
        return 0;
    }

    ttp_debug_target.gw = vv;
    return 0;
}

static int ttp_param_target_use_gw_get (char *buf, const struct kernel_param *kp)
{
    return snprintf (buf, 300, "%d\n", ttp_debug_target.gw);
}

static const struct kernel_param_ops ttp_param_target_use_gw_ops = {
    .set = ttp_param_target_use_gw_set,
    .get = ttp_param_target_use_gw_get,
};

module_param_cb (use_gw, &ttp_param_target_use_gw_ops, NULL, 0644);
MODULE_PARM_DESC (use_gw, "   target uses l3-gateway (default=0, or 1)");


static int ttp_param_nhmac_set (const char *val, const struct kernel_param *kp)
{
    int rv = 0;
    u8  mac[ETH_ALEN];

    for (rv = 0; rv < ETH_ALEN; rv++) {
        mac[rv] = simple_strtol (val, NULL, 16) & 0xff;
        val += 2;
        if (rv < (ETH_ALEN - 1) && (*val != ':')) {
            return -EINVAL;
        }
        if ((rv == (ETH_ALEN - 1) && (*val != '\n' && *val != '\0'))) {
            return -EINVAL;
        }
        val++;
    }

    if (!is_valid_ether_addr (mac)) {
        return -EADDRNOTAVAIL;
    }
    if (ether_addr_equal (ttp_nhmac, mac)) {
        return -EADDRINUSE;
    }
    if (!ether_addr_equal (ttp_nhmac, mac)) {
        ether_addr_copy (ttp_nhmac, mac);
    }
    return 0;
}

static int ttp_param_nhmac_get (char *buf, const struct kernel_param *kp)
{
    return snprintf (buf, 300, "%*phC\n", ETH_ALEN, ttp_nhmac);
}

static const struct kernel_param_ops ttp_param_nhmac_ops = {
    .set = ttp_param_nhmac_set,
    .get = ttp_param_nhmac_get,
};

module_param_cb (nhmac, &ttp_param_nhmac_ops, &ttp_nhmac, 0444);
MODULE_PARM_DESC (nhmac, "    next-hop mac address (format: xx:xx:xx:xx:xx:xx)");


static int ttp_param_encap_set (const char *val, const struct kernel_param *kp)
{
    int vv = 0;

    if ((0 != kstrtoint (val, 10, &vv)) || vv < 0 || vv > 1) {
        return -EINVAL;
    }
    if ((ttp_ipv4_encap = vv)) { /* assign and check true */
        ttp_etype_dev.type = htons (ETH_P_IP);
    }

    return 0;
}

static const struct kernel_param_ops ttp_param_encap_ops = {
    .set = ttp_param_encap_set,
    .get = param_get_int,
};

module_param_cb (ipv4, &ttp_param_encap_ops, &ttp_ipv4_encap, 0444);
MODULE_PARM_DESC (ipv4, "     encap mode for TTP: 0 = TTPoE, 1 = TTPoIPv4 (read-only)");


/* Scan ipv4 addresses on 'dev' */
static void ttp_param_scan_ipv4 (const struct net_device *dev)
{
    u64 kid;
    struct in_ifaddr *ifa4;
    u32 node, mask = inet_make_mask (ttp_ipv4_pfxlen);
    u8 mac[ETH_ALEN];

    if (ttp_debug_source.ipa) {
        return;
    }
    rcu_read_lock ();
    for (ifa4 = rcu_dereference (dev->ip_ptr->ifa_list); ifa4;
         ifa4 = rcu_dereference (ifa4->ifa_next)) {

        TTP_DB2 ("`-> Try: ipv4:%pI4/%d\n", &ifa4->ifa_address, ifa4->ifa_prefixlen);
        if ((ifa4->ifa_address & mask) == (ttp_ipv4_prefix & mask)) {
            ttp_debug_source.ipa = ifa4->ifa_address;
            node = ifa4->ifa_address & ~mask; /* get host part */
            ttp_mac_from_shim (mac, (u8 *)&node + 1);
            kid = ttp_tag_key_make (mac, 0, false, ttp_ipv4_encap);
            TTP_DBG ("%s: Source-IP:%pI4 mytag:[0x%016llx]\n", __FUNCTION__,
                     &ifa4->ifa_address, cpu_to_be64 (kid));
            break;
        }
    }
    rcu_read_unlock ();
}


static int ttp_param_prefix_set (const char *val, const struct kernel_param *kp)
{
    const char *tail;
    int ln;

    if (!ttp_dev) {
        TTP_LOG ("%s: Error: ttp-dev required to set prefix\n", __FUNCTION__);
        return -EINVAL;
    }
    if (!ttp_ipv4_encap) {
        TTP_LOG ("%s: Error: ttp ipv4-encap required to set prefix\n", __FUNCTION__);
        return -EINVAL;
    }
    else if (!(ln = strcspn (val, "\n"))) {
        return 0;
    }
    else if (((char *)val)[ln] == '\n') { /* consume trailing \n from shell */
        ((char *)val)[ln] = '\0';
    }
    /* parse ipv4 address */
    if (!in4_pton (val, -1, (u8 *)&ttp_ipv4_prefix, -1, &tail)) {
        TTP_LOG ("%s: Error: failed to decode prefix '%s'\n", __FUNCTION__, val);
        ttp_ipv4_prefix = 0;
        return -EINVAL;
    }
    /* check if left-over string is valid in CIDR notation */
    else if (*tail == '/') {
        if (kstrtoint (tail + 1, 10, &ttp_ipv4_pfxlen)) {
            TTP_LOG ("%s: Error: failed to decode prefix '%s'\n", __FUNCTION__, val);
            return -EINVAL;
        }
        /* only support prefixes {8,32} */
        if (ttp_ipv4_pfxlen < 8 || ttp_ipv4_pfxlen > 32) {
            TTP_LOG ("%s: Error: invalid prefix length: %d in prefix '%s'\n",
                     __FUNCTION__, ttp_ipv4_pfxlen, val);
            return -EINVAL;
        }
    }
    /* reject any string not matching either x.x.x.x or x.x.x.x/y format ipv4 prefix */
    else if (*tail != '\0') {
        TTP_LOG ("%s: Error: invalid prefix string '%s'\n", __FUNCTION__, val);
        return -EINVAL;
    }
    if (!ttp_ipv4_pfxlen) { /* default len = 8 if param not in CIDR notation */
        ttp_ipv4_pfxlen = 8;
    }

    ttp_ipv4_prefix &= inet_make_mask (ttp_ipv4_pfxlen);
    TTP_DB1 ("%s: set ttp ipv4-prefix: %pI4/%d\n", __FUNCTION__, &ttp_ipv4_prefix,
             ttp_ipv4_pfxlen);

    /* This can get called before __init when params are specified on mod-load cmdline */ 
    if (!ttp_etype_dev.dev) {
        if (!(ttp_etype_dev.dev = dev_get_by_name (&init_net, ttp_dev))) {
            TTP_LOG ("Error: Couldn't 'get' dev:%s - unloading\n", ttp_dev);
            return -ENODEV;
        }
        TTP_LOG ("'get' dev:%s - success mac:%*phC\n", ttp_dev, ETH_ALEN,
                 ttp_etype_dev.dev->dev_addr);
        dev_put (ttp_etype_dev.dev);
        ether_addr_copy (ttp_debug_source.mac, ttp_etype_dev.dev->dev_addr);
        TTP_DBG ("%s: ttp-source:%*phC dev:%s\n", __FUNCTION__, ETH_ALEN,
                 ttp_debug_source.mac, ttp_etype_dev.dev->name);
    }
    ttp_param_scan_ipv4 (ttp_etype_dev.dev);
    return 0;
}

static int ttp_param_prefix_get (char *buf, const struct kernel_param *kp)
{
    if (ttp_ipv4_prefix) {
        return snprintf (buf, 30, "%pI4/%d\n", &ttp_ipv4_prefix, ttp_ipv4_pfxlen);
    }
    else {
        return snprintf (buf, 30, "0\n");
    }
}

static const struct kernel_param_ops ttp_param_prefix_ops = {
    .set = ttp_param_prefix_set,
    .get = ttp_param_prefix_get,
};

module_param_cb (prefix, &ttp_param_prefix_ops, &ttp_ipv4_prefix, 0644);
MODULE_PARM_DESC (prefix, "   ipv4 prefix: (A.B.C.D/N)");


static int ttp_param_ipv4_sip_get (char *buf, const struct kernel_param *kp)
{
    return snprintf (buf, 30, "%pI4\n", &ttp_debug_source.ipa);
}

static const struct kernel_param_ops ttp_param_ipv4_sip_ops = {
    .set = ttp_param_dummy_set,
    .get = ttp_param_ipv4_sip_get,
};

module_param_cb (ipv4_sip, &ttp_param_ipv4_sip_ops, &ttp_debug_source.ipa, 0444);
MODULE_PARM_DESC (ipv4_sip, "   ipv4 src-ip: (A.B.C.D)");


static int ttp_param_ipv4_dip_get (char *buf, const struct kernel_param *kp)
{
    return snprintf (buf, 30, "%pI4\n", &ttp_debug_target.ipa);
}

static const struct kernel_param_ops ttp_param_ipv4_dip_ops = {
    .set = ttp_param_dummy_set,
    .get = ttp_param_ipv4_dip_get,
};

module_param_cb (ipv4_dip, &ttp_param_ipv4_dip_ops, &ttp_debug_target.ipa, 0444);
MODULE_PARM_DESC (ipv4_dip, "   ipv4 dst-ip: (A.B.C.D)");


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


static int ttp_param_stats_get (char *buf, const struct kernel_param *kp)
{
    return snprintf
        (buf, 500,
         "frames: %d  [control: %d  payload: %d  drops: %d]\n"
         "  adds: bkt-0: %-6d bkt-1: %-6d\n"
         "  dels: bkt-0: %-6d bkt-1: %-6d\n"
         "  pool: %d\n"
         " queue: %d\n"
         " timer: %d\n"
         "  nocq: %d\n"
         " evlog: %d\n"
         "ovr_fl: %d\n"
         "und_fl: %d\n"
         "err_ev: %d\n"
         "err_lg: %d\n"
         "skb_ct: %d\n"
         "skb_rx: %d\n"
         "skb_tx: %d\n",

         atomic_read (&ttp_stats.frm_ct),
         atomic_read (&ttp_stats.drp_ct),
         atomic_read (&ttp_stats.pld_ct),

         atomic_read (&ttp_stats.frm_ct) -
         atomic_read (&ttp_stats.pld_ct) -
         atomic_read (&ttp_stats.drp_ct),

         atomic_read (&ttp_stats.adds[0]),
         atomic_read (&ttp_stats.adds[1]),
         atomic_read (&ttp_stats.dels[0]),
         atomic_read (&ttp_stats.dels[1]),

         ttp_stats.pool,
         ttp_stats.queue,
         ttp_stats.timer,
         ttp_stats.nocq,
         ttp_stats.evlog,

         ttp_stats.ovr_fl,
         ttp_stats.und_fl,

         ttp_stats.err_ev,
         ttp_stats.err_lg,

         atomic_read (&ttp_stats.skb_ct),
         atomic_read (&ttp_stats.skb_rx),
         atomic_read (&ttp_stats.skb_tx));
}

static const struct kernel_param_ops ttp_param_stats_ops = {
    .set = param_set_int,
    .get = ttp_param_stats_get,
};

module_param_cb (stats, &ttp_param_stats_ops, NULL, 0444);
MODULE_PARM_DESC (stats, "    ttp counters (read-only)");


static int ttp_debug_target_force_close (struct ttpoe_host_info *tg)
{
    if (is_valid_ether_addr (tg->mac)) {
        TTP_LOG ("noc_debug: Sending TTP_CLOSE to target.vc: %*phC.%d\n",
                 ETH_ALEN, tg->mac, tg->vc);
        /* best effort, no error checking */
        ttpoe_noc_debug_tx (NULL, NULL, 0, TTP_EV__TXQ__TTP_CLOSE, &ttp_debug_target);
    }
    return 0;
}

static int ttp_param_debug_target_set (const char *val, const struct kernel_param *kp)
{
    u64 kid;
    int rv;
    u32 target;

    if (ttp_ipv4_encap && !ttp_ipv4_prefix) {
        TTP_LOG ("%s: Error: ttp ipv4-encap required to set target\n", __FUNCTION__);
        return -EINVAL;
    }
    if ((rv = kstrtouint (val, 16 /* base16 */, &target))) {
        TTP_LOG ("%s: Error: Invalid target format:'%s'\n", __FUNCTION__,
                 strim ((char *)val));
        return rv;
    }
    /* set target = 0 closes existing connection to target */
    if (0 == target) {
        ttp_debug_target_force_close (&ttp_debug_target);
        memset (&ttp_debug_target, 0, sizeof (ttp_debug_target));
        return 0;
    }

    /* construct target mac address: upper 24b oui */
    eth_zero_addr (ttp_debug_target.mac);
    ttp_debug_target.mac[0] = Tesla_Mac_Oui0;
    ttp_debug_target.mac[1] = Tesla_Mac_Oui1;
    ttp_debug_target.mac[2] = Tesla_Mac_Oui2;

    /* lower 24b */
    ttp_debug_target.mac[3] = (target >> 16) & 0xff;
    ttp_debug_target.mac[4] = (target >>  8) & 0xff;
    ttp_debug_target.mac[5] = (target >>  0) & 0xff;

    if (!is_valid_ether_addr (ttp_debug_target.mac)) {
        return -EADDRNOTAVAIL;
    }
    if (ttp_ipv4_encap) {
        memcpy ((u8 *)&ttp_debug_target.ipa + 1, &ttp_debug_target.mac[3], ETH_ALEN/2);
        ttp_debug_target.ipa &= ~inet_make_mask (ttp_ipv4_pfxlen);
        ttp_debug_target.ipa |= ttp_ipv4_prefix;
        TTP_LOG ("%s: target.ip:%pI4\n", __FUNCTION__, &ttp_debug_target.ipa);
    }
    else {
        TTP_LOG ("%s: target.mac:%*phC\n", __FUNCTION__, ETH_ALEN, ttp_debug_target.mac);
    }

    ttp_debug_target.ve = 1;    /* force valid for debug 'target' */
    return ttp_debug_target_enable (&kid, &ttp_debug_target);
}

static const struct kernel_param_ops ttp_param_debug_target_ops = {
    .set = ttp_param_debug_target_set,
    .get = ttp_param_target_mac_get,
};

module_param_cb (target, &ttp_param_debug_target_ops, NULL, 0644);
MODULE_PARM_DESC (target, "   ttp debug target (24b hex value: "
                  "e.g. target=012345 => [oui]:01:23:45)");


static const struct kernel_param_ops ttp_param_tag_seq_ops = {
    .set = param_set_int,
    .get = param_get_int,
};

/* read-only parameter; must be set at module-load */
module_param_cb (tag_seq, &ttp_param_tag_seq_ops, &ttp_tag_seq_init_val, 0444);
MODULE_PARM_DESC (tag_seq, "  starting value of tag seq number (default=1)");


static int ttp_param_wkstep_set (const char *val, const struct kernel_param *kp)
{
    int num = 0;

    if ('S' == toupper (val[0])) {
        TTP_LOG ("%s: got 'step' command\n", __FUNCTION__);
        ttp_stats.wkq_st = ttp_stats.wkq_sz;
        schedule_work (&ttp_global_root_head.work_queue);
        return 0;
    }

    if ((0 != kstrtoint (val, 10, &num)) || num < 0 || num > 100) {
        TTP_LOG ("%s: got %d (out of range [1-100])\n", __FUNCTION__, num);
        return -EINVAL;
    }

    if (0 == num) {
        TTP_LOG ("%s: got 'run' command\n", __FUNCTION__);
    }
    else {
        TTP_LOG ("%s: got %d\n", __FUNCTION__, num);
    }

    ttp_stats.wkq_st = ttp_stats.wkq_sz = num;

    if (--ttp_stats.wkq_st) {
        schedule_work (&ttp_global_root_head.work_queue);
    }

    return param_set_int (val, kp);
}

static int ttp_param_wkstep_get (char *buf, const struct kernel_param *kp)
{
    if (0 == ttp_stats.wkq_sz) {
        return snprintf (buf, 300, "work-queue step-size: 0 (default disabled)\n");
    }
    else {
        return snprintf (buf, 300, "work-queue step-size: %d (steps-left: %d)\n",
                         ttp_stats.wkq_sz, ttp_stats.wkq_st);
    }
}

static const struct kernel_param_ops ttp_param_wkstep_ops = {
    .set = ttp_param_wkstep_set,
    .get = ttp_param_wkstep_get,
};

module_param_cb (wkstep, &ttp_param_wkstep_ops, &ttp_stats.wkq_sz, 0644);
MODULE_PARM_DESC (wkstep, "   ttp fsm single-step state (default=0)\n"
                  "                          write '0' run freely; '[1-100]'"
                  " set step-size; 's' step");
