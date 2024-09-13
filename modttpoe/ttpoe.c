// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Tesla Inc. All rights reserved.
 *
 * TTP (TTPoE) A reference implementation of Tesla Transport Protocol (TTP) that runs directly
 *             over Ethernet Layer-2 Network. This is implemented as a Loadable Kernel Module
 *             that establishes a TTP-peer connection with another instance of the same module
 *             running on another Linux machine on the same Layer-2 network. Since TTP runs
 *             over Ethernet, it is often referred to as TTP Over Ethernet (TTPoE).
 *
 *             The Protocol is specified to work at high bandwidths over 100Gbps and is mainly
 *             designed to be implemented in Hardware as part of Tesla's DOJO project.
 *
 *             This public release of the TTP software implementation is aligned with the patent
 *             disclosure and public release of the main TTP Protocol specification. Users of
 *             this software module must take into consideration those disclosures in addition
 *             to the license agreement mentioned here.
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
 *             05/11/2023 dntundlam@tesla.com, "ttpoe layers - network, transport, and payload"
 *             07/11/2023 dntundlam@tesla.com, "functional state-machine, added tests"
 *             09/29/2023 dntundlam@tesla.com, "final touches"
 *             09/10/2024 dntundlam@tesla.com, "sync with TTP_Opcodes.pdf [rev 1.5]"
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

#include <linux/ctype.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/inet.h>
#include <linux/etherdevice.h>
#include <linux/types.h>
#include <linux/bitops.h>
#include <linux/cred.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/module.h>
#include <linux/proc_fs.h>

#include <ttp.h>

#include "ttpoe.h"
#include "fsm.h"
#include "tags.h"
#include "noc.h"
#include "print.h"


#if (TTP_NOC_BUF_SIZE>1024)
#error "TTPoE max-noc buffer is 1K"
#endif

u8  Tesla_Mac_Oui0;
u8  Tesla_Mac_Oui1;
u8  Tesla_Mac_Oui2;
u32 Tesla_Mac_Oui;

static int ttpoe_skb_recv_func (struct sk_buff *, struct net_device *dev,
                                struct packet_type *pt, struct net_device *odev);

static struct packet_type ttpoe_etype_tesla __read_mostly = {
    .dev  = NULL,               /* set via module-param */
    .type = htons (TESLA_ETH_P_TTPOE), /* Match only Tesla ethertype */
    .func = ttpoe_skb_recv_func,
    .ignore_outgoing = true,
};


bool ttp_random_flip (int pct)
{
    u32 rnd;

    if (pct) {
        rnd = get_random_u32 ();
        /* get it down to 10 bits ==> 1000 */
        rnd = (rnd & 0xffff) ^ (rnd >> 16);
        rnd = (rnd &  0x3ff) ^ (rnd >> 10);
        if (rnd < ((pct * (1<<10)) / 100)) {
            return true;
        }
    }

    return false;
}


u8 *ttp_skb_aloc (struct sk_buff **skbp, const int nl)
{
    u8 *buf;
    struct sk_buff *skb;
    u16 frame_len;

    frame_len = ETH_HLEN + TTP_TTH_HDR_LEN + nl;

    if (!(skb = alloc_skb (frame_len + TTP_IP_HEADROOM, GFP_KERNEL))) {
        return NULL;
    }

    skb_reserve (skb, TTP_IP_HEADROOM);
    skb_reset_mac_header (skb);
    skb_set_network_header (skb, ETH_HLEN);
    skb->protocol = htons (TESLA_ETH_P_TTPOE);

    buf = skb_put (skb, TTP_TTH_HDR_LEN);
    skb_put (skb, nl);

    skb->len = max (frame_len, TTP_MIN_FRAME_LEN);
    skb_trim (skb, skb->len);
    skb_set_tail_pointer (skb, skb->len);

    skb->dev = ttpoe_etype_tesla.dev;

    TTP_DBG ("%s: len:%d dev:%s\n", __FUNCTION__, skb->len, skb->dev->name);

    *skbp = skb;
    return buf;
}


void ttp_skb_xmit (struct sk_buff *skb)
{
    if (!skb) {
        return;
    }

    if (ttp_shutdown) {
        TTP_LOG ("%s: <<- Tx frame dropped: ttp is shutdown\n", __FUNCTION__);
        kfree_skb (skb);
        return;
    }

    ttpoe_parse_print (skb, TTP_TX);
    atomic_inc (&ttp_stats.skb_tx);

    TTP_DBG ("`-> %s: <<- Tx frame: len:%d dev:%s\n", __FUNCTION__, skb->len, skb->dev->name);
    dev_queue_xmit (skb);
}


void ttp_skb_drop (struct sk_buff *skb)
{
    kfree_skb (skb);
}


TTP_NOINLINE static u8 *ttp_tsk_move (struct ttp_fsm_event *ev, struct sk_buff **skb)
{
    if (skb && ev && ev->tsk) {
        *skb = ev->tsk;
        (*skb)->data = ev->psi.skb_dat;
        (*skb)->len = ev->psi.skb_len;
        skb_reset_mac_header (*skb);
        ev->tsk = NULL;

        return ev->psi.skb_dat;
    }

    return NULL;
}


void ttp_tsk_bind (struct ttp_fsm_event *ev, const struct ttp_fsm_event *qev)
{
    if (ev && qev) {
        ev->psi = qev->psi;
        if (qev->tsk) {
            ev->tsk = qev->tsk;
            refcount_inc (&ev->tsk->users);
        }
    }
}


static void ttp_setup_ethhdr (struct ethhdr *eth,
                              const u8 *dmac_low, const u8 *gwmac)
{
    eth->h_proto = htons (TESLA_ETH_P_TTPOE);

    BUG_ON (!(eth && (dmac_low || gwmac)));

    memmove (eth->h_source, ttpoe_etype_tesla.dev->dev_addr, ETH_ALEN);

    if (dmac_low) {
        eth->h_dest[0] = Tesla_Mac_Oui0;
        eth->h_dest[1] = Tesla_Mac_Oui1;
        eth->h_dest[2] = Tesla_Mac_Oui2;
        eth->h_dest[3] = dmac_low[0];
        eth->h_dest[4] = dmac_low[1];
        eth->h_dest[5] = dmac_low[2];
    }
    else if (gwmac) {
        memmove (eth->h_dest, gwmac, ETH_ALEN);
    }
}


static void ttpoe_fill_hdr_offsets (const struct sk_buff *skb, struct ttp_pkt_info *pi)
{
    pi->tth_off = 0;
    pi->tsh_off = sizeof (struct ttp_tsla_type_hdr) + pi->tth_off;
    pi->ttp_off = sizeof (struct ttp_tsla_shim_hdr) + pi->tsh_off;
    pi->noc_off = sizeof (struct ttp_transport_hdr) + pi->ttp_off;
    pi->dat_off = sizeof (struct ttp_ttpoe_noc_hdr) + pi->noc_off;
}


void ttp_skb_pars (const struct sk_buff *skb, struct ttp_frame_hdr *fh, struct ttp_pkt_info *pi)
{
    u8 *pkp;
    struct ttp_pkt_info lpi = {0};
    struct ttp_frame_hdr lfh;

    if (!fh) {
        fh = &lfh;
    }
    if (!pi) {
        pi = &lpi;
    }

    ttpoe_fill_hdr_offsets (skb, pi);

    pkp = skb->data;
    fh->eth = (struct ethhdr *)pkp;
    fh->tth = (struct ttp_tsla_type_hdr *)(pkp + ETH_HLEN);
    fh->tsh = (struct ttp_tsla_shim_hdr *)(pkp + ETH_HLEN + pi->tsh_off);
    fh->ttp = (struct ttp_transport_hdr *)(pkp + ETH_HLEN + pi->ttp_off);
    fh->noc = (struct ttp_ttpoe_noc_hdr *)(pkp + ETH_HLEN + pi->noc_off);
    fh->dat = (struct ttp_ttpoe_noc_dat *)(pkp + ETH_HLEN + pi->dat_off);

    pi->rxi_seq = ntohl (fh->ttp->conn_rx_seq);
    pi->txi_seq = ntohl (fh->ttp->conn_tx_seq);
    pi->noc_len = ntohs (fh->tsh->length) - TTP_HEADERS_LEN;
}


bool ttp_skb_pars_get_gw_flag (const struct sk_buff *skb)
{
    struct ttp_frame_hdr frh;

    if (!skb) {
        return false;
    }

    ttp_skb_pars (skb, &frh, NULL);
    return frh.tth->l3gw;
}


TTP_NOINLINE int static ttpoe_parse_check (const struct sk_buff *skb)
{
    struct ttp_frame_hdr frh;
    int ttp_min_len;

    ttp_min_len = ETH_HLEN + TTP_TTH_HDR_LEN;
    if (skb->len < ttp_min_len) {
        TTP_LOG ("pre_parser: UNEXPECTED ERROR: frame len (%d) too small (expected %d)\n",
                 skb->len, ttp_min_len);
        return -1;
    }

    ttp_skb_pars (skb, &frh, NULL);
    if (frh.eth->h_proto != htons (TESLA_ETH_P_TTPOE)) {
        TTP_LOG ("pre_parser: UNEXPECTED ethertype: %04x\n", ntohs (frh.eth->h_proto));
        return -1;
    }
    if (frh.tth->tthl != TTP_PROTO_TTHL) {
        TTP_LOG ("pre_parser: Incorrect TTH len:%d\n", frh.tth->tthl);
        return -1;
    }

    return 0;
}


int ttp_skb_dequ (void)
{
    struct sk_buff *skb;
    struct ttp_fsm_event *ev;
    struct ttp_pkt_info pif;
    struct ttp_frame_hdr frh;
    u8 mac[ETH_ALEN];

    if (!(skb = skb_dequeue (&ttp_global_root_head.skb_head))) {
        return 0;
    }

    memset (&frh, 0, sizeof (frh));
    memset (&pif, 0, sizeof (pif));

    ttpoe_parse_print (skb, TTP_RX);

    ttp_skb_pars (skb, &frh, &pif);

    if (!TTP_OPCODE_IS_VALID (frh.ttp->conn_opcode)) {
        TTP_LOG ("pre_parser: INVALID opcode:%d\n", frh.ttp->conn_opcode);
        ttp_skb_drop (skb);
        return 0;
    }

    if (!TTP_VC_ID__IS_VALID (frh.ttp->conn_vc)) {
        TTP_LOG ("pre_parser: INVALID vc-id:%d\n", frh.ttp->conn_vc);
        ttp_skb_drop (skb);
        return 0;
    }

    if (!ttp_evt_pget (&ev)) {
        ttp_skb_drop (skb);
        return 0;
    }

    atomic_inc (&ttp_stats.frm_ct);
    atomic_inc (&ttp_stats.skb_ct);

    ev->rsk = skb;
    ev->psi = pif;
    ev->evt = TTP_OPCODE_TO_EVENT (frh.ttp->conn_opcode);

    if (frh.tth->l3gw) {
        if (!is_valid_ether_addr (ttp_debug_gwmac.mac)) {
            ether_addr_copy (ttp_debug_gwmac.mac, frh.eth->h_source); /* learn gwmac */
        }

        ttp_mac_from_shim (mac, frh.tsh->src_node);
        ev->kid = ttp_tag_key_make (mac, frh.ttp->conn_vc, 1);
    }
    else {
        ev->kid = ttp_tag_key_make (frh.eth->h_source, frh.ttp->conn_vc, 0);
    }

    ttp_evt_enqu (ev);
    TTP_EVLOG (ev, TTP_LG__PKT_RX, frh.ttp->conn_opcode);

    return 1;
}


u8 *ttp_skb_prep (struct sk_buff **skbp,
                  struct ttp_fsm_event *qev, enum ttp_opcodes_enum op)
{
    u16 nl;
    u8 *rv;
    struct sk_buff *skb = NULL;
    struct ttp_link_tag *lt, qlt;
    struct ttp_pkt_info pif;
    struct ttp_frame_hdr frh;

    BUG_ON ((TTP_OP__TTP_PAYLOAD == op) && !qev->psi.noc_len);

    memset (&frh, 0, sizeof (frh));
    memset (&pif, 0, sizeof (pif));

    nl = (TTP_OP__TTP_PAYLOAD == op) ? qev->psi.noc_len : 0;

    if (!(lt = ttp_rbtree_tag_get (qev->kid))) {
        qlt._rkid = qev->kid;   /* no tag: resolve mac_low via qev */
        lt = &qlt;
    }

    if (!(rv = ttp_tsk_move (qev, &skb))) {
        if (!(rv = ttp_skb_aloc (&skb, nl))) {
            return NULL;
        }
    }

    BUG_ON (!skb);
    ttp_skb_pars (skb, &frh, &pif);

    TTP_DBG ("%s: len:%d rx:%d tx:%d noc-len:%d ev:%s\n", __FUNCTION__,
             skb->len, pif.rxi_seq, pif.txi_seq, nl, TTP_EVENT_NAME (qev->evt));

    /* setup L4 */
    frh.ttp->conn_opcode = op;
    frh.ttp->conn_vc = lt->vci;

    /* setup L2.5 */
    frh.tth->styp = 0;
    frh.tth->vers = 0;
    frh.tth->tthl = TTP_PROTO_TTHL;
    frh.tth->l3gw = lt->gwy;
    frh.tth->resv = 0;
    frh.tth->tot_len = htons (nl + TTP_TTH_HDR_LEN);

    /* setup L2 */
    if (lt->gwy) {
        ttp_setup_ethhdr (frh.eth, NULL, ttp_debug_gwmac.mac);
    }
    else {
        ttp_setup_ethhdr (frh.eth, lt->mac, NULL);
    }

    /* setup tesla shim */
    memmove (frh.tsh->src_node, &ttpoe_etype_tesla.dev->dev_addr[3], ETH_ALEN/2);
    memmove (frh.tsh->dst_node, lt->mac, ETH_ALEN/2);
    frh.tsh->length = htons (nl + TTP_HEADERS_LEN); /* noc-length + shim + transport */

    skb->dev = ttpoe_etype_tesla.dev;

    BUG_ON (ttpoe_parse_check (skb));
    BUG_ON (qev->tsk);

    *skbp = skb;
    return rv;
}


TTP_NOINLINE static int ttpoe_skb_recv (struct sk_buff *skb)
{
    struct ethhdr *eth;

    if (!skb) {
        return 0;
    }

    TTP_DBG ("%s: ->> Rx frame: len:%d dev:%s\n", __FUNCTION__,
             skb->len, skb->dev->name);

    eth = (struct ethhdr *)skb_mac_header (skb);
    if (!ether_addr_equal (eth->h_dest, ttpoe_etype_tesla.dev->dev_addr)) {
        ttpoe_parse_print (skb, TTP_RX);
        if (is_multicast_ether_addr (eth->h_dest)) {
            TTP_LOG ("%s: gw_mac_adv: %*phC\n", __FUNCTION__, ETH_ALEN, eth->h_source);
            ttp_debug_gwmac.gw = 1;
            ttp_debug_gwmac.ve = 1;
            ether_addr_copy (ttp_debug_gwmac.mac, eth->h_source);
            ttp_gwmacadv ();
        }
        else {
            TTP_LOG ("%s: UNEXPECTED ether-dest: %*phC\n", __FUNCTION__, ETH_ALEN, eth->h_dest);
        }
        kfree_skb (skb);
        return 0;
    }

    if (ttpoe_parse_check (skb)) {
        kfree_skb (skb);
        return 0;
    }

    TTP_RUN_SPIN_LOCKED ({
        skb_queue_tail (&ttp_global_root_head.skb_head, skb);
        atomic_inc (&ttp_stats.skb_rx);
    });

    schedule_work (&ttp_global_root_head.work_queue);

    return 0;
}


TTP_NOINLINE static int ttpoe_skb_recv_func (struct sk_buff *skb, struct net_device *dev,
                                             struct packet_type *pt, struct net_device *odev)
{
    if (ttp_shutdown) {
        TTP_LOG ("%s: ->> Rx frame dropped: ttp is shutdown\n", __FUNCTION__);
        kfree_skb (skb);
        return 0;
    }

    if (skb_headroom (skb) < TTP_IP_HEADROOM) {
        if (pskb_expand_head (skb, TTP_IP_HEADROOM, 0, GFP_ATOMIC)) {
            TTP_LOG ("%s:    Drop frame: insufficient headroom\n", __FUNCTION__);
            kfree_skb (skb);
            return 0;
        }
    }

    skb_push (skb, ETH_HLEN);
    return ttpoe_skb_recv (skb);
}

TTP_NOINLINE static int __init ttpoe_oui_detect (void)
{
    if ((ttpoe_etype_tesla.dev->dev_addr[0] == TESLA_MAC_OUI0) &&
        (ttpoe_etype_tesla.dev->dev_addr[1] == TESLA_MAC_OUI1) &&
        (ttpoe_etype_tesla.dev->dev_addr[2] == TESLA_MAC_OUI2))
    {
        Tesla_Mac_Oui0 = TESLA_MAC_OUI0;
        Tesla_Mac_Oui1 = TESLA_MAC_OUI1;
        Tesla_Mac_Oui2 = TESLA_MAC_OUI2;
        Tesla_Mac_Oui  = TESLA_MAC_OUI;
        return 0;
    }

    if ((ttpoe_etype_tesla.dev->dev_addr[0] == TESLA_MAC2_OUI0) &&
        (ttpoe_etype_tesla.dev->dev_addr[1] == TESLA_MAC2_OUI1) &&
        (ttpoe_etype_tesla.dev->dev_addr[2] == TESLA_MAC2_OUI2))
    {
        Tesla_Mac_Oui0 = TESLA_MAC2_OUI0;
        Tesla_Mac_Oui1 = TESLA_MAC2_OUI1;
        Tesla_Mac_Oui2 = TESLA_MAC2_OUI2;
        Tesla_Mac_Oui  = TESLA_MAC2_OUI;
        return 0;
    }

    return -EINVAL;
}


TTP_NOINLINE static int __init ttpoe_init (void)
{
    u64 me;

#if (TTP_TTH_MATCHES_IPH == 1)
    if (sizeof (struct ttp_tsla_type_hdr) != sizeof (struct iphdr)) {
        TTP_LOG ("Error: tth size != iph size - unloading\n");
        return -EINVAL;
    }
#endif

    if (!ttp_dev || (!(ttpoe_etype_tesla.dev = dev_get_by_name (&init_net, ttp_dev)))) {
        TTP_LOG ("Error: Could not get dev (%s) - unloading\n", ttp_dev ?: "<unspecified>");
        return -ENODEV;
    }
    dev_put (ttpoe_etype_tesla.dev);

    if (!(ttpoe_etype_tesla.dev->flags & IFF_UP)) {
        TTP_LOG ("Error: Device dev (%s) is DOWN - unloading\n", ttp_dev);
        return -ENETDOWN;
    }

    if (ttpoe_oui_detect ()) {
        TTP_LOG ("Error: dev (%s) mac-oui is not Tesla - unloading\n", ttp_dev);
        return -EINVAL;
    }

    if (ttpoe_proc_init ()) {
        return -EINVAL;
    }

    if (ttpoe_noc_debug_init ()) {
        return -EINVAL;
    }

    ttp_fsm_init ();

    me = ttp_tag_key_make (ttpoe_etype_tesla.dev->dev_addr, 0, 0);
    TTP_DBG ("ttp-source:%*phC [0x%016llx] device:%s\n",
             ETH_ALEN, ttpoe_etype_tesla.dev->dev_addr,
             cpu_to_be64 (me), ttpoe_etype_tesla.dev->name);
    ether_addr_copy (ttp_debug_source.mac, ttpoe_etype_tesla.dev->dev_addr);

    dev_add_pack (&ttpoe_etype_tesla);

    TTP_EVLOG (NULL, TTP_LG__TTP_INIT, TTP_OP__invalid);

    TTP_DBG ("-------------------- Module modttpoe.ko loaded --------------------+\n");
    ttp_shutdown = 0;           /* no-shut ttp */

    return 0;
}


TTP_NOINLINE static void __exit ttpoe_exit (void)
{
    ttp_shutdown = 1;

    dev_remove_pack (&ttpoe_etype_tesla);

    ttp_fsm_exit ();
    ttpoe_noc_debug_exit ();
    ttpoe_proc_exit ();

    TTP_DBG ("~~~~~~~~~~~~~~~~~~~ Module modttpoe.ko unloaded ~~~~~~~~~~~~~~~~~~~+\n");
}


module_init (ttpoe_init);
module_exit (ttpoe_exit);

MODULE_AUTHOR ("dntundlam@tesla.com");
MODULE_DESCRIPTION ("TTP Over Ethernet");
MODULE_VERSION ("1.0");
MODULE_LICENSE ("GPL");
