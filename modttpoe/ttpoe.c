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
 *
 *  /########################         /#######
 * |__  ##__/_  ##__/ ##___ ##       | ##____/
 *    | ##|   | ##| | ##   \## ######| ##
 *    | ##|   | ##| | ####### ##__  ## #####
 *    | ##|   | ##| | ##___/| ##  \ ## ##__/
 *    | ##|   | ##| | ##    | ##  | ## ##
 *    | ##|   | ##| | ##    |  ######/ #######
 *    |__/    |__/  |__/     \______/|_______/
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
#include <linux/netdevice.h>
#include <linux/inet.h>
#include <linux/etherdevice.h>
#include <linux/inetdevice.h>
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


#if (TTP_NOC_BUF_SIZE>1024)
#error "TTPoE max-noc buffer is 1K"
#endif

const u8  Tesla_Mac_Oui0 = TESLA_MAC_OUI0;
const u8  Tesla_Mac_Oui1 = TESLA_MAC_OUI1;
const u8  Tesla_Mac_Oui2 = TESLA_MAC_OUI2;
const u32 Tesla_Mac_Oui  = TESLA_MAC_OUI;

int ttp_shutdown = 1; /* 'DOWN' by default - enabled at init after checking */
int ttp_drop_pct = 0; /* drop percent = 0% by default */

char *ttp_dev;
u32   ttp_ipv4_prefix;
u32   ttp_ipv4_pfxlen;
int   ttp_ipv4_encap;
u8    ttp_nhmac[ETH_ALEN] = {0x98, 0xed, 0x5c, 0xff, 0xff, 0xff};


static int ttpoe_skb_recv_func (struct sk_buff *, struct net_device *dev,
                                struct packet_type *pt, struct net_device *odev);

struct packet_type ttp_etype_dev __read_mostly = {
    .dev  = NULL,                      /* set via module-param 'dev' */
    .type = htons (TESLA_ETH_P_TTPOE), /* can change via module-param 'ipv4' at init */
    .func = ttpoe_skb_recv_func,
    .ignore_outgoing = true,
};


/* allocate skb, add space for noc-payload of length 'nl', returning ptr to noc-buf */
u8 *ttp_skb_aloc (struct sk_buff **skbp, int nl)
{
    u8 *buf;
    struct sk_buff *skb;
    u16 frame_len, hdrs_len;

    if (ttp_ipv4_encap) {
        hdrs_len = TTP_IP_HDRS_LEN;
    }
    else {
        hdrs_len = TTP_TTH_HDR_LEN;
    }
    frame_len = ETH_HLEN + hdrs_len + nl;

    if (!(skb = alloc_skb (frame_len + TTP_IP_HEADROOM, GFP_ATOMIC))) {
        return NULL;
    }

    skb_reserve (skb, TTP_IP_HEADROOM);
    skb_reset_mac_header (skb);
    skb_set_network_header (skb, ETH_HLEN);
    skb->protocol = htons (TESLA_ETH_P_TTPOE);

    buf = skb_put (skb, hdrs_len);
    skb_put (skb, nl);

    skb->len = max (frame_len, TTP_MIN_FRAME_LEN);
    skb_trim (skb, skb->len);
    skb_set_tail_pointer (skb, skb->len);

    skb->dev = ttp_etype_dev.dev;

    TTP_VBG ("%s: len:%d dev:%s etype:0x%04x\n", __FUNCTION__,
             skb->len, skb->dev->name, htons (skb->protocol));
    *skbp = skb;
    return buf;
}


/* wrapper around skb-dev_queue_xmit with some logging and stats; no drops */
void ttp_skb_xmit (struct sk_buff *skb)
{
    struct ttp_frame_hdr frh;

    if (!skb) {
        return;
    }
    if (ttp_shutdown) {
        TTP_DBG ("%s: <<- Tx frame dropped: ttp is shutdown\n", __FUNCTION__);
        ttp_skb_drop (skb);
        return;
    }

    ttp_skb_pars (skb, &frh, NULL);
    TTP_DBG ("%s: <<- Tx frame: len:%d dev:%s\n", __FUNCTION__, skb->len, skb->dev->name);
    ttpoe_parse_print (skb, TTP_TX, 1);
    atomic_inc (&ttp_stats.skb_tx);
    dev_queue_xmit (skb);
}


void ttp_skb_drop (struct sk_buff *skb)
{
    kfree_skb (skb);
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


static bool ttp_tsk_move (struct ttp_fsm_event *ev, struct sk_buff **skb)
{
    if (!skb || !ev || !ev->tsk) {
        return false;
    }
    TTP_RUN_SPIN_LOCKED ({
        *skb = ev->tsk;
        (*skb)->data = ev->psi.skb_dat;
        (*skb)->len = ev->psi.skb_len;
        /* restore protocol and device as they can change when skb is re-queued */
        (*skb)->protocol = htons (TESLA_ETH_P_TTPOE);
        (*skb)->dev = ttp_etype_dev.dev;
        skb_reset_mac_header (*skb);
        ev->tsk = NULL;
    });
    return true;
}


static void ttp_setup_ethhdr (struct ethhdr *eth, const u8 *dmac_low, const u8 *nhmac)
{
    eth->h_proto = htons (TESLA_ETH_P_TTPOE);

    BUG_ON (!(eth && (dmac_low || nhmac)));

    memmove (eth->h_source, ttp_etype_dev.dev->dev_addr, ETH_ALEN);

    if (dmac_low) {
        eth->h_dest[0] = Tesla_Mac_Oui0;
        eth->h_dest[1] = Tesla_Mac_Oui1;
        eth->h_dest[2] = Tesla_Mac_Oui2;
        eth->h_dest[3] = dmac_low[0];
        eth->h_dest[4] = dmac_low[1];
        eth->h_dest[5] = dmac_low[2];
    }
    else if (nhmac) {
        memmove (eth->h_dest, nhmac, ETH_ALEN);
    }
}


static void ttpoe_fill_hdr_offsets (const struct sk_buff *skb, struct ttp_pkt_info *pi)
{
    if (skb->protocol == htons (TESLA_ETH_P_TTPOE)) {
        pi->tsh_off = sizeof (struct ttp_tsla_type_hdr);
    }
    else if (skb->protocol == htons (ETH_P_IP)) {
        pi->tsh_off = sizeof (struct iphdr);
    }

    pi->ttp_off = sizeof (struct ttp_tsla_shim_hdr) + pi->tsh_off;
    pi->noc_off = sizeof (struct ttp_transport_hdr) + pi->ttp_off;
    pi->dat_off = sizeof (struct ttp_ttpoe_noc_hdr) + pi->noc_off;
}


u16 ttp_skb_pars (const struct sk_buff *skb, struct ttp_frame_hdr *fh,
                  struct ttp_pkt_info *pi)
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

    if (skb->protocol == htons (TESLA_ETH_P_TTPOE)) {
        fh->tth = (struct ttp_tsla_type_hdr *)(pkp + ETH_HLEN);
    }
    else if (skb->protocol == htons (ETH_P_IP)) {
        fh->ip4 = (struct iphdr *)(pkp + ETH_HLEN);
    }
    else {
        TTP_VBG ("%s: len:%d dev:%s etype:0x%04x\n", __FUNCTION__,
                 skb->len, skb->dev->name, htons (skb->protocol));
        return 0; /* unsupported Etype */
    }

    fh->tsh = (struct ttp_tsla_shim_hdr *)(pkp + ETH_HLEN + pi->tsh_off);
    fh->ttp = (struct ttp_transport_hdr *)(pkp + ETH_HLEN + pi->ttp_off);
    fh->noc = (struct ttp_ttpoe_noc_hdr *)(pkp + ETH_HLEN + pi->noc_off);
    fh->dat = (struct ttp_ttpoe_noc_dat *)(pkp + ETH_HLEN + pi->dat_off);

    pi->rxi_seq = ntohl (fh->ttp->conn_rx_seq);
    pi->txi_seq = ntohl (fh->ttp->conn_tx_seq);
    if (ntohs (fh->tsh->length) >= TTP_HEADERS_LEN) {
        pi->noc_len = ntohs (fh->tsh->length) - TTP_HEADERS_LEN;
    }

    return ntohs (skb->protocol);
}


TTP_NOINLINE
static int ttpoe_parse_check (struct sk_buff *skb)
{
    struct ttp_frame_hdr frh;

    ttp_skb_pars (skb, &frh, NULL);

    switch (ntohs (skb->protocol)) {
    case TESLA_ETH_P_TTPOE:
        if (frh.tth->tthl != TTP_PROTO_TTHL) {
            TTP_DB1 ("%s: Incorrect TTP-Hdr-Len:%d\n", __FUNCTION__, frh.tth->tthl);
            return -1;
        }
        if (ttp_verbose > 2) {
            ttp_print_eth_hdr (frh.eth);
            ttp_print_shim_hdr (frh.tsh);
        }
        break;
    case ETH_P_IP:
        if (frh.ip4->ihl != TTP_IPHDR_IHL) {
            TTP_DB1 ("%s: Incorrect IP-Hdr-len:%d\n", __FUNCTION__, frh.ip4->ihl);
            return -1;
        }
        if (frh.ip4->protocol != TTP_IPPROTO_TTP) {
            return -1;
        }
        if (ttp_verbose > 2) {
            ttp_print_eth_hdr (frh.eth);
            ttp_print_ipv4_hdr (frh.ip4);
            ttp_print_shim_hdr (frh.tsh);
        }
        break;
    default:
        TTP_DB1 ("%s: UNEXPECTED: 0x%04x\n", __FUNCTION__, ntohs (skb->protocol));
        return -1;
        break;
    }

    if (skb->len < TTP_MIN_FRAME_LEN) {
        TTP_DB1 ("%s: UNEXPECTED ERROR: frame len (%d) too small (expected %d)\n",
                 __FUNCTION__, skb->len, TTP_MIN_FRAME_LEN);
        return -1;
    }
    return 0;
}


int ttp_skb_dequ (void)
{
    u32 node;
    bool gw = false;
    bool t4 = false;
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

    ttpoe_parse_print (skb, TTP_RX, 1);
    ttp_skb_pars (skb, &frh, &pif);

    switch (ntohs (skb->protocol)) {
    case TESLA_ETH_P_TTPOE:
        gw = frh.tth->l3gw;
        break;
    case ETH_P_IP:
        if (frh.ip4->protocol != TTP_IPPROTO_TTP) {
            ttp_skb_drop (skb);
            return 0;
        }
        t4 = true;
        break;
    default:
        ttp_skb_drop (skb);
        return 0;
    }

    if (!TTP_OPCODE_IS_VALID (frh.ttp->conn_opcode)) {
        TTP_DBG ("%s: INVALID opcode:%d\n", __FUNCTION__, frh.ttp->conn_opcode);
        ttp_skb_drop (skb);
        return 0;
    }

    if (!TTP_VC_ID__IS_VALID (frh.ttp->conn_vc)) {
        TTP_DBG ("%s: INVALID vc-id:%d\n", __FUNCTION__, frh.ttp->conn_vc);
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

    if (gw) { /* via ttp-gw */
        ttp_prepare_mac_with_oui (mac, Tesla_Mac_Oui, frh.tsh->src_node);
        ev->kid = ttp_tag_key_make (mac, frh.ttp->conn_vc, true, false);
        TTP_DB2 ("%s: 0x%016llx (gw) dst:%*phC <- src:%*phC\n", __FUNCTION__,
                  cpu_to_be64 (ev->kid),
                  ETH_ALEN/2, frh.tsh->dst_node, ETH_ALEN/2, frh.tsh->src_node);
    }
    else if (t4) { /* ipv4-encap mode */
        node = frh.ip4->saddr & ~inet_make_mask (ttp_ipv4_pfxlen); /* get host part */
        ttp_prepare_mac_with_oui (mac, Tesla_Mac_Oui, (u8 *)&node + 1);
        ev->kid = ttp_tag_key_make (mac, frh.ttp->conn_vc, false, true);
        TTP_DB1 ("%s: 0x%016llx (ipv4) dst:%pI4 <- src:%pI4\n", __FUNCTION__,
                  cpu_to_be64 (ev->kid), &frh.ip4->daddr, &frh.ip4->saddr);
    }
    else { /* raw ethernet - node-id is from src-mac in ethernet header */
        ev->kid = ttp_tag_key_make (frh.eth->h_source, frh.ttp->conn_vc, false, false);
        TTP_DB1 ("%s: 0x%016llx (eth) dst:%*phC <- src:%*phC\n", __FUNCTION__,
                  cpu_to_be64 (ev->kid),
                  ETH_ALEN/2, &frh.eth->h_dest[3], ETH_ALEN/2, &frh.eth->h_source[3]);
    }

    ttp_evt_enqu (ev);
    TTP_EVLOG (ev, TTP_LG__PKT_RX, frh.ttp->conn_opcode);

    return 1;
}


/* sets up ipv4 encap info, returns true on success; false on failure - no drops */
static bool ttp_ipv4_encap_setup (struct sk_buff *skb)
{
    u32 sip, dip;
    struct ttp_frame_hdr frh;

    if (!ttp_ipv4_prefix) {
        TTP_DBG ("%s: <<- Tx frame dropped: ipv4 'prefix' not set\n", __FUNCTION__);
        goto end;
    }
    if (!ttp_debug_source.ipa) {
        TTP_DBG ("%s: <<- Tx frame dropped: ipv4 'src-ip' not set\n", __FUNCTION__);
        goto end;
    }
    if (!is_valid_ether_addr (ttp_nhmac)) {
        TTP_DBG ("%s: <<- Tx frame dropped: ipv4 'nh-mac' unknown\n", __FUNCTION__);
        goto end;
    }

    sip = ttp_debug_source.ipa;
    skb->protocol = htons (ETH_P_IP);
    ttp_skb_pars (skb, &frh, NULL);

    /* set dip from dmac[23:0] in network order */
    memcpy ((u8 *)&dip + 1, &frh.eth->h_dest[3], ETH_ALEN/2);
    dip &= ~inet_make_mask (ttp_ipv4_pfxlen); /* retain host part */
    dip |= ttp_ipv4_prefix;

    /* prepare IP header */
    if (ttp_prepare_ipv4 ((u8 *)frh.ip4, ntohs (frh.tsh->length), sip, dip)) {
        ether_addr_copy (frh.eth->h_dest, ttp_nhmac);
        frh.eth->h_proto = skb->protocol;
        TTP_DB1 ("%s: skb-len:%d\n", __FUNCTION__, skb->len);
        return true;
    }

end:
    return false;
}


/* sets up net info, returns true on success; false on failure - no drops */
static bool ttp_skb_net_setup (struct sk_buff *skb, struct ttp_link_tag *lt, u16 nl,
                               enum ttp_opcodes_enum op)
{
    u32 node;
    bool gw = false;
    bool t4 = false;
    struct ttp_frame_hdr frh;

    memset (&frh, 0, sizeof (frh));
    if (!ttp_skb_pars (skb, &frh, NULL)) {
        ttpoe_parse_print (skb, TTP_TX, 1);
        return false;
    }

    /* setup L4 */
    gw = lt ? lt->gw3 : 1; /* set gw when no tag - directly reply to skb */
    if (!gw) { /* gw flag takes priority */
        t4 = lt ? lt->tp4 : 0; /* do not assume ipv4 encap when lt == NULL */
    }
    frh.ttp->conn_opcode = op;
    frh.ttp->conn_vc = lt ? lt->vci : TTP_MAX_VCID;

    if (t4) { /* ip4 encap */
        if (!ttp_debug_source.ipa) {
            TTP_DBG ("%s: Drop tx-frame dropped: ipv4 'src-ip' not set\n", __FUNCTION__);
            return false;
        }
        if (lt) {
            ttp_setup_ethhdr (frh.eth, lt->mac, NULL);
        }
        else if (is_valid_ether_addr (ttp_nhmac)) {
            ttp_setup_ethhdr (frh.eth, NULL, ttp_nhmac);
        }
        else {
            return false;
        }
        /* not printing eth-hdr here as it will be overwritten in ipv4-encap-setup */
    }
    else if (gw) { /* via ttp-gw */
        if (!is_valid_ether_addr (ttp_nhmac)) {
            TTP_DBG ("%s: Drop tx-frame: nhmac unknown\n", __FUNCTION__);
            return false;
        }
        ttp_prepare_tth ((u8 *)frh.tth, nl + TTP_TTH_HDR_LEN, true);
        ttp_setup_ethhdr (frh.eth, NULL, ttp_nhmac);
        if (ttp_verbose > 2) {
            ttp_print_eth_hdr (frh.eth);
        }
    }
    else if (lt) { /* raw ethernet */
        ttp_prepare_tth ((u8 *)frh.tth, nl + TTP_TTH_HDR_LEN, false);
        ttp_setup_ethhdr (frh.eth, lt->mac, NULL);
        if (ttp_verbose > 2) {
            ttp_print_eth_hdr (frh.eth);
        }
    }
    else { /* pedantic: since all three {gw, t4, lt} can't be NULL */
        return false;
    }

    /* setup tesla shim */
    if (t4) {
        node = ttp_debug_source.ipa & ~inet_make_mask (ttp_ipv4_pfxlen);
        memmove (frh.tsh->src_node, (u8 *)&node + 1, ETH_ALEN/2);
    }
    else {
        memmove (frh.tsh->src_node, &ttp_etype_dev.dev->dev_addr[3], ETH_ALEN/2);
    }
    if (lt) {
        memmove (frh.tsh->dst_node, lt->mac, ETH_ALEN/2);
    }
    else {
        memset (frh.tsh->dst_node, 0, ETH_ALEN/2);
    }
    frh.tsh->length = htons (nl + TTP_HEADERS_LEN); /* noc-length + shim + transport */

    TTP_DB2 ("%s: skb-len:%d gw:%d ip4:%d\n", __FUNCTION__, skb->len, gw, t4);
    return true;
}


/* returns true on success; false on failure - AND - drops any skb alloced/retrieved */
bool ttp_skb_prep (struct sk_buff **skbp, struct ttp_fsm_event *qev,
                   enum ttp_opcodes_enum op)
{
    u16 nl = 0;
    bool new = false; /* skb moved */
    struct sk_buff *skb = NULL;
    struct ttp_link_tag *lt, qlt;

    if (TTP_OP__TTP_PAYLOAD == op) {
        if (!(nl = qev->psi.noc_len)) {
            return false;
        }
    }
    if (!(lt = ttp_rbtree_tag_get (qev->kid))) {
        qlt._rkid = qev->kid;   /* no tag: resolve mac_low via qev */
        lt = &qlt;
    }
    if (!ttp_tsk_move (qev, &skb)) {
        if (!ttp_skb_aloc (&skb, nl)) {
            return false;
        }
        new = true;
    }
    if (!ttp_skb_net_setup (skb, lt, nl, op)) {
        ttp_skb_drop (skb);
        return false;
    }
    if (ttp_ipv4_encap) { /* ipv4 encap mode */
        if (!ttp_ipv4_encap_setup (skb)) {
            ttp_skb_drop (skb);
            return false;
        }
    }
    if (ttpoe_parse_check (skb)) {
        ttp_skb_drop (skb);
        return false;
    }
    BUG_ON (qev->tsk);
    *skbp = skb;

    TTP_DB2 ("%s: new:%d skb-len:%d noc-len:%d ev:%s etype:0x%04x\n", __FUNCTION__,
              new, skb->len, nl, TTP_EVENT_NAME (qev->evt), htons (skb->protocol));
    return true;
}


/* not used in ipv4-encap mode */
static void ttp_gwmacadv (struct sk_buff *skb)
{
    if (ttp_skb_net_setup (skb, NULL, 2, TTP_OP__TTP_OPEN_NACK)) {
        ttpoe_parse_print (skb, TTP_TX, 3);
        dev_queue_xmit (skb);
    }
    else {
        ttp_skb_drop (skb);
    }
}


static int ttp_skb_recv (struct sk_buff *skb)
{
    struct ethhdr *eth;

    if (!skb) {
        return 0;
    }
    if (ttp_rnd_flip (ttp_drop_pct)) {
        TTP_DBG ("%s: ->! Rx frame dropped: rate:%d%%\n", __FUNCTION__, ttp_drop_pct);
        ttp_skb_drop (skb);
        return 0;
    }
    if (ttpoe_parse_check (skb)) {
        ttp_skb_drop (skb);
        return 0;
    }
    if (ttp_ipv4_encap) {
        if (!ttp_ipv4_prefix) {
            TTP_DBG ("%s: ->> Rx frame dropped: ipv4 'prefix' not set\n", __FUNCTION__);
            ttp_skb_drop (skb);
            return 0;
        }
        TTP_DB2 ("%s: ->> Rx frame: len:%d dev:%s\n", __FUNCTION__,
                  skb->len, skb->dev->name);
        ttpoe_parse_print (skb, TTP_RX, 2);
        if (skb->protocol != htons (ETH_P_IP)) {
            TTP_DBG ("%s: UNEXPECTED ether-type: 0x%04x\n", __FUNCTION__,
                     ntohs (skb->protocol));
            ttp_skb_drop (skb);
            return 0;
        }
        goto recv;
    }

    eth = (struct ethhdr *)skb_mac_header (skb);
    if (!ether_addr_equal (eth->h_dest, ttp_etype_dev.dev->dev_addr)) {
        if (skb->protocol != htons (TESLA_ETH_P_TTPOE)) {
            TTP_DBG ("%s: UNEXPECTED ether-type: 0x%04x\n", __FUNCTION__,
                     ntohs (skb->protocol));
            ttp_skb_drop (skb);
            return 0;
        }
        if (!is_multicast_ether_addr (eth->h_dest)) {
            TTP_DBG ("%s: UNEXPECTED ether-dest: %*phC\n", __FUNCTION__,
                     ETH_ALEN, eth->h_dest);
            ttp_skb_drop (skb);
            return 0;
        }
        TTP_DB2 ("%s: ->> Rx (gw-ctrl) frame: len:%d dev:%s\n", __FUNCTION__,
                  skb->len, skb->dev->name);
        ttpoe_parse_print (skb, TTP_RX, 2);
        if (!ether_addr_equal (ttp_nhmac, eth->h_source)) {
            TTP_DB2 ("%s: Learnt nhmac:%*phC\n", __FUNCTION__, ETH_ALEN, eth->h_source);
            ether_addr_copy (ttp_nhmac, eth->h_source);
        }
        TTP_DB2 ("%s: Learnt nhmac:%*phC\n", __FUNCTION__, ETH_ALEN, eth->h_source);
        TTP_DB2 ("%s: <<- Tx (gw-ctrl) frame: len:%d dev:%s\n", __FUNCTION__,
                  skb->len, skb->dev->name);
        ttp_gwmacadv (skb);
        return 0;
    }

recv:
    TTP_DBG ("%s: ->> Rx frame: len:%d dev:%s\n", __FUNCTION__, skb->len, skb->dev->name);

    TTP_RUN_SPIN_LOCKED ({
        skb_queue_tail (&ttp_global_root_head.skb_head, skb);
        atomic_inc (&ttp_stats.skb_rx);
    });

    schedule_work (&ttp_global_root_head.work_queue);

    return 0;
}


TTP_NOINLINE
static int ttpoe_skb_recv_func (struct sk_buff *skb, struct net_device *dev,
                                struct packet_type *pt, struct net_device *odev)
{
    if (ttp_shutdown) {
        TTP_DBG ("%s: ->> Rx frame dropped: ttp is shutdown\n", __FUNCTION__);
        ttp_skb_drop (skb);
        return 0;
    }

    if (skb_headroom (skb) < TTP_IP_HEADROOM) {
        if (pskb_expand_head (skb, TTP_IP_HEADROOM, 0, GFP_ATOMIC)) {
            TTP_DBG ("%s:    Drop frame: insufficient headroom\n", __FUNCTION__);
            ttp_skb_drop (skb);
            return 0;
        }
    }

    skb_push (skb, ETH_HLEN);
    return ttp_skb_recv (skb);
}

TTP_NOINLINE
static int __init ttpoe_oui_detect (void)
{
    if ((ttp_etype_dev.dev->dev_addr[0] == TESLA_MAC_OUI0) &&
        (ttp_etype_dev.dev->dev_addr[1] == TESLA_MAC_OUI1) &&
        (ttp_etype_dev.dev->dev_addr[2] == TESLA_MAC_OUI2))
    {
        return 0;
    }
    return -EINVAL;
}


TTP_NOINLINE
static int __init ttpoe_init (void)
{
    int rc;
    u64 me;

    if (!ttp_dev || (!(ttp_etype_dev.dev = dev_get_by_name (&init_net, ttp_dev)))) {
        TTP_LOG ("Error: Couldn't 'get' dev:%s - unloading\n", ttp_dev ?: "<unspec>");
        return -ENODEV;
    }
    dev_put (ttp_etype_dev.dev);

    if (!(ttp_etype_dev.dev->flags & IFF_UP)) {
        TTP_LOG ("Error: Device dev (%s) is DOWN - unloading\n", ttp_dev);
        return -ENETDOWN;
    }

    if (!ttp_ipv4_encap) {
        if ((rc = ttpoe_oui_detect ())) {
            TTP_LOG ("Error: dev (%s) mac-oui is not Tesla - unloading\n", ttp_dev);
            return rc;
        }
    }

    if ((rc = ttpoe_proc_init ())) {
        return rc;
    }

    if ((rc = ttpoe_noc_debug_init ())) {
        ttpoe_proc_cleanup ();
        return rc;
    }

    ttp_fsm_init ();

    if (!ttp_ipv4_pfxlen) {
        me = ttp_tag_key_make (ttp_debug_source.mac, 0, false, ttp_ipv4_encap);
        TTP_DBG ("%s: ttp-source:%*phC mytag:[0x%016llx]\n"
                 "       dev:%s nhmac:%*phC ipv4:%d\n", __FUNCTION__, ETH_ALEN,
                 ttp_debug_source.mac, cpu_to_be64 (me),
                 ttp_etype_dev.dev->name, ETH_ALEN, ttp_nhmac, ttp_ipv4_encap);
    }

    dev_add_pack (&ttp_etype_dev);

    TTP_EVLOG (NULL, TTP_LG__TTP_INIT, TTP_OP__invalid);

    TTP_LOG ("-------------------- Module modttpoe.ko loaded --------------------+\n");
    ttp_shutdown = 0;           /* no-shut ttp */

    return 0;
}


TTP_NOINLINE
static void __exit ttpoe_exit (void)
{
    ttp_shutdown = 1;
    dev_remove_pack (&ttp_etype_dev);
    ttp_fsm_exit ();
    ttpoe_noc_debug_exit ();
    ttpoe_proc_exit ();

    TTP_LOG ("~~~~~~~~~~~~~~~~~~~ Module modttpoe.ko unloaded ~~~~~~~~~~~~~~~~~~~+\n");
}


module_init (ttpoe_init);
module_exit (ttpoe_exit);

MODULE_AUTHOR ("dntundlam@tesla.com");
MODULE_DESCRIPTION ("TTP Over Ethernet");
MODULE_VERSION ("1.0");
MODULE_LICENSE ("GPL");
