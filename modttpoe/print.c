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

#ifndef __KERNEL__
#define __KERNEL__
#endif

#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/module.h>
#include <linux/seq_file.h>
#include <net/addrconf.h>

#include <ttp.h>

#include "ttpoe.h"
#include "fsm.h"
#include "tags.h"
#include "print.h"

char *ttp_opcode_names[] =
{
    [TTP_OP__TTP_OPEN]        = "TTP_OPEN",
    [TTP_OP__TTP_OPEN_ACK]    = "TTP_OPEN_ACK",
    [TTP_OP__TTP_OPEN_NACK]   = "TTP_OPEN_NACK",
    [TTP_OP__TTP_CLOSE]       = "TTP_CLOSE",
    [TTP_OP__TTP_CLOSE_ACK]   = "TTP_CLOSE_ACK",
    [TTP_OP__TTP_CLOSE_NACK]  = "TTP_CLOSE_NACK",
    [TTP_OP__TTP_PAYLOAD]     = "TTP_PAYLOAD",
    [TTP_OP__TTP_ACK]         = "TTP_ACK",
    [TTP_OP__TTP_NACK]        = "TTP_NACK",
    [TTP_OP__TTP_NACK_FULL]   = "TTP_NACK_FULL",
    [TTP_OP__TTP_NACK_NOLINK] = "TTP_NACK_NOLINK",

    [TTP_OP__invalid]         = "__int_/_none__",
};

char *ttp_state_names[] =
{
    [TTP_ST__stay]       = "__stay__",

    [TTP_ST__CLOSED]     = "CLOSED",
    [TTP_ST__OPEN_SENT]  = "OPEN_SENT",
    [TTP_ST__OPEN_RECD]  = "OPEN_RECD",
    [TTP_ST__OPEN]       = "OPEN",
    [TTP_ST__CLOSE_SENT] = "CLOSE_SENT",
    [TTP_ST__CLOSE_RECD] = "CLOSE_RECD",

    [TTP_ST__invalid]    = "__invalid__",
};

char *ttp_state_names_short[] =
{
    [TTP_ST__stay]       = "__",

    [TTP_ST__CLOSED]     = "CL", /* closed */
    [TTP_ST__OPEN_SENT]  = "OS",
    [TTP_ST__OPEN_RECD]  = "OR",
    [TTP_ST__OPEN]       = "OP", /* open */
    [TTP_ST__CLOSE_SENT] = "CS",
    [TTP_ST__CLOSE_RECD] = "CR",

    [TTP_ST__invalid]    = "xx",
};


char *ttp_event_names[] =
{
    [TTP_EV__null]                  = "__null__",

    [TTP_EV__TXQ__TTP_OPEN]         = "TXQ__TTP_OPEN",
    [TTP_EV__TXQ__TTP_CLOSE]        = "TXQ__TTP_CLOSE",
    [TTP_EV__TXQ__TTP_PAYLOAD]      = "TXQ__TTP_PAYLOAD",

    [TTP_EV__TXQ__REPLAY_DATA]      = "TXQ__REPLAY_DATA",
    [TTP_EV__TXQ__REPLAY_CLOSE]     = "TXQ__REPLAY_CLOSE",

    [TTP_EV__RXQ__TTP_OPEN]         = "RXQ__TTP_OPEN",
    [TTP_EV__RXQ__TTP_OPEN_ACK]     = "RXQ__TTP_OPEN_ACK",
    [TTP_EV__RXQ__TTP_OPEN_NACK]    = "RXQ__TTP_OPEN_NACK",
    [TTP_EV__RXQ__TTP_CLOSE]        = "RXQ__TTP_CLOSE",
    [TTP_EV__RXQ__TTP_CLOSE_ACK]    = "RXQ__TTP_CLOSE_ACK",
    [TTP_EV__RXQ__TTP_CLOSE_NACK]   = "RXQ__TTP_CLOSE_NACK",
    [TTP_EV__RXQ__TTP_PAYLOAD]      = "RXQ__TTP_PAYLOAD",
    [TTP_EV__RXQ__TTP_ACK]          = "RXQ__TTP_ACK",
    [TTP_EV__RXQ__TTP_NACK]         = "RXQ__TTP_NACK",
    [TTP_EV__RXQ__TTP_NACK_FULL]    = "RXQ__TTP_NACK_FULL",
    [TTP_EV__RXQ__TTP_NACK_NOLINK]  = "RXQ__TTP_NACK_NOLINK",

    [TTP_EV__RXQ__TTP_UNXP_PAYLD]   = "RXQ__TTP_UNXP_PAYLOAD",

    [TTP_EV__AKQ__OPEN_ACK]         = "AKQ__OPEN_ACK",
    [TTP_EV__AKQ__OPEN_NACK]        = "AKQ__OPEN_NACK",
    [TTP_EV__AKQ__CLOSE_ACK]        = "AKQ__CLOSE_ACK",
    [TTP_EV__AKQ__CLOSE_NACK]       = "AKQ__CLOSE_NACK",
    [TTP_EV__AKQ__ACK]              = "AKQ__ACK",
    [TTP_EV__AKQ__NACK]             = "AKQ__NACK",

    [TTP_EV__INQ__TIMEOUT]          = "int__TIMEOUT",
    [TTP_EV__INQ__VICTIM]           = "int__VICTIM",
    [TTP_EV__INQ__FOUND_WAY]        = "int__FOUND_WAY",
    [TTP_EV__INQ__NO_WAY]           = "int__NO_WAY",
    [TTP_EV__INQ__ALLOC_TAG]        = "int__ALLOC_TAG",
    [TTP_EV__INQ__NO_TAG]           = "int__NO_TAG",
    [TTP_EV__INQ__YES_QUIESCED]     = "int__YES_QUIESCED",
    [TTP_EV__INQ__NOT_QUIESCED]     = "int__NOT_QUIESCED",

    [TTP_EV__invalid]               = "__invalid__",
};

char *ttp_response_names[] =
{
    [TTP_RS__none]         = "__none__",

    [TTP_RS__OPEN]         = "OPEN",
    [TTP_RS__OPEN_ACK]     = "OPEN_ACK",
    [TTP_RS__OPEN_NACK]    = "OPEN_NACK",
    [TTP_RS__CLOSE]        = "CLOSE",
    [TTP_RS__CLOSE_ACK]    = "CLOSE_ACK",
    [TTP_RS__CLOSE_XACK]   = "CLOSE_?ACK",
    [TTP_RS__REPLAY_DATA]  = "REPLAY_DATA",
    [TTP_RS__PAYLOAD]      = "PAYLOAD",
    [TTP_RS__PAYLOAD2]     = "PAYLOAD2",
    [TTP_RS__ACK]          = "ACK",
    [TTP_RS__NACK]         = "NACK",
    [TTP_RS__NACK_NOLINK]  = "NACK_NOLINK",
    [TTP_RS__NOC_FAIL]     = "NOC_FAIL",
    [TTP_RS__NOC_END]      = "NOC_END",
    [TTP_RS__ILLEGAL]      = "ILLEGAL",
    [TTP_RS__INTERRUPT]    = "INTERRUPT",
    [TTP_RS__DROP]         = "DROP",
    [TTP_RS__STALL]        = "STALL",

    [TTP_RS__invalid]      = "__invalid__",
};

char *ttp_evlog_names[] =
{
    [TTP_LG__TTP_INIT]              = "TTP_INIT",

    [TTP_LG__TTP_LINK_UP]           = "TTP_LINK_UP",
    [TTP_LG__TTP_LINK_DOWN]         = "TTP_LINK_DOWN",

    [TTP_LG__PKT_RX]                = "NETWORK_PKT_RX",
    [TTP_LG__PKT_TX]                = "NETWORK_PKT_TX",
    [TTP_LG__PKT_DROP]              = "NETWORK_SKB_XX",

    [TTP_LG__NOC_LINK_OPEN]         = "NOC_LINK_OPEN",
    [TTP_LG__NOC_LINK_CLOSE]        = "NOC_LINK_CLOSE",

    [TTP_LG__NOC_PAYLOAD_TX]        = "NOC_PAYLOAD_TX",
    [TTP_LG__NOC_PAYLOAD_RX]        = "NOC_PAYLOAD_RX",
    [TTP_LG__NOC_PAYLOAD_ENQ]       = "NOC_PAYLOAD_ENQ",
    [TTP_LG__NOC_PAYLOAD_REQ]       = "NOC_PAYLOAD_REQ",
    [TTP_LG__NOC_PAYLOAD_DUP]       = "NOC_PAYLOAD_DUP",
    [TTP_LG__NOC_PAYLOAD_DROP]      = "NOC_PAYLOAD_DROP",
    [TTP_LG__NOC_PAYLOAD_FREE]      = "NOC_PAYLOAD_FREE",

    [TTP_LG__SH_TIMER_START]        = "SHORT_TMR_START",
    [TTP_LG__SH_TIMER_RESTART]      = "SHORT_TMR_RESTRT",
    [TTP_LG__LN_TIMER_START]        = "LONG_TMR_START",
    [TTP_LG__LN_TIMER_RESTART]      = "LONG_TMR_RESTRT",
    [TTP_LG__TIMER_TIMEOUT]         = "TIMER_TIMEOUT",
    [TTP_LG__TIMER_DELETE]          = "TIMER_DELETE",

    [TTP_LG__invalid]               = "__invalid__",
};

char *ttp_evlog_glyph[] =
{
    [TTP_LG__TTP_INIT]              = "__up-",

    [TTP_LG__TTP_LINK_UP]           = "L_^##",
    [TTP_LG__TTP_LINK_DOWN]         = "L#v__",

    [TTP_LG__PKT_RX]                = ">>>>>",
    [TTP_LG__PKT_TX]                = "<<<<<",
    [TTP_LG__PKT_DROP]              = "xxxxx",

    [TTP_LG__NOC_LINK_OPEN]         = "__Jvv",
    [TTP_LG__NOC_LINK_CLOSE]        = "vvL__",

    [TTP_LG__NOC_PAYLOAD_TX]        = "vvvvv",
    [TTP_LG__NOC_PAYLOAD_RX]        = "^^^^^",
    [TTP_LG__NOC_PAYLOAD_ENQ]       = "<<-vv",
    [TTP_LG__NOC_PAYLOAD_REQ]       = "<<-@v",
    [TTP_LG__NOC_PAYLOAD_DUP]       = "x-\"-x",
    [TTP_LG__NOC_PAYLOAD_DROP]      = "xxxxx",
    [TTP_LG__NOC_PAYLOAD_FREE]      = "-free",

    [TTP_LG__SH_TIMER_START]        = "!S_-_",
    [TTP_LG__SH_TIMER_RESTART]      = "!S->>",
    [TTP_LG__LN_TIMER_START]        = "!L_-_",
    [TTP_LG__LN_TIMER_RESTART]      = "!L->>",
    [TTP_LG__TIMER_TIMEOUT]         = "!*___",
    [TTP_LG__TIMER_DELETE]          = "!x___",

    [TTP_LG__invalid]               = " ??? ",
};

char *ttp_evlog_dir[] =
{
    [TTP_LG__TTP_INIT]              = ".\'.",

    [TTP_LG__TTP_LINK_UP]           = "..^",
    [TTP_LG__TTP_LINK_DOWN]         = "..v",

    [TTP_LG__PKT_RX]                = ">rx",
    [TTP_LG__PKT_TX]                = "<tx",
    [TTP_LG__PKT_DROP]              = "xxx",

    [TTP_LG__NOC_LINK_OPEN]         = "..(",
    [TTP_LG__NOC_LINK_CLOSE]        = "..)",

    [TTP_LG__NOC_PAYLOAD_TX]        = "-tx",
    [TTP_LG__NOC_PAYLOAD_RX]        = "-rx",
    [TTP_LG__NOC_PAYLOAD_ENQ]       = "-vv",
    [TTP_LG__NOC_PAYLOAD_REQ]       = "-@v",
    [TTP_LG__NOC_PAYLOAD_DUP]       = "-\"-",
    [TTP_LG__NOC_PAYLOAD_DROP]      = "-x-",
    [TTP_LG__NOC_PAYLOAD_FREE]      = "-fr",

    [TTP_LG__SH_TIMER_START]        = " _!",
    [TTP_LG__SH_TIMER_RESTART]      = " @!",
    [TTP_LG__LN_TIMER_START]        = " !!",
    [TTP_LG__LN_TIMER_RESTART]      = "@!!",
    [TTP_LG__TIMER_TIMEOUT]         = "!!!",
    [TTP_LG__TIMER_DELETE]          = " x!",

    [TTP_LG__invalid]               = "",
};


static u8 ttpoe_prbuf[TTPOE_PRBUF_MAX];
int ttp_verbose = -1;


TTP_NOTRACE void ttpoe_pretty_print_data (const u8 *caption, const int bpl,
                                          const u8 *buf, const int buflen)
{
    int len = buflen;

    if (ttp_verbose < 2) {
        return;
    }

    do {
        scnprintf (ttpoe_prbuf, TTPOE_PRBUF_MAX, "%*ph", min (len, bpl), buf);
        TTP_DBG ("%s%s\n", caption, ttpoe_prbuf);

        buf += bpl;
        if (len > bpl) {
            len -= bpl;
        }
        else {
            len = 0;
        }
    } while (len);
}


TTP_NOTRACE void ttp_print_evt_val (struct seq_file *seq, const struct ttp_fsm_event *ev)
{
    struct ttp_link_tag  *lt = NULL;

    if (!(lt = ttp_rbtree_tag_get (ev->kid)) ||
        (ev->evt <= TTP_EV__null || ev->evt >= TTP_EV__invalid))
        return;

    BUG_ON (!ev || (ev->rsk && ev->tsk));

    seq_printf (seq, "%3d %1d %1d %2d %3d ->%-17s%2d"
                "   %6d   %6d   %6d   %6d   0x%016llx.%d  %s\n",
                lt->hvl,
                1,
                lt->bkt,
                lt->vci,
                TTP_EVENTS_INDX_OF (ev),
                TTP_EVENT_NAME (ev->evt),
                lt->gw3 | (lt->tp4 << 1),
                ev->psi.rxi_seq,
                ev->psi.txi_seq,
                lt->retire_id,
                ev->psi.noc_len,
                cpu_to_be64 (ev->kid),
                ev->idx,
                TTP_EVENTS_FENCE_TO_STR (ev->mrk));
}

TTP_NOTRACE void ttp_print_tag_val (struct seq_file *seq, const struct ttp_link_tag *lt)
{
    struct ttp_fsm_event *ev;

    if (!seq || !lt || !lt->valid) {
        return;
    }

    seq_printf (seq, "%3d %1d %1d %2d  %2s  %d %d %d    %02x:%02x:%02x %2d"
                "   %6d   %6d   %6d   %6d   0x%016llx\n",
                lt->hvl,
                lt->valid,
                lt->bkt,
                lt->vci,
                TTP_STATE_NAME_SH (lt->state),
                lt->tct,
                lt->txt,
                lt->try,
                lt->mac[0], lt->mac[1], lt->mac[2],
                lt->gw3 | (lt->tp4 << 1),
                lt->rx_seq_id,
                lt->tx_seq_id,
                lt->retire_id,
                atomic_read (&lt->opens),
                cpu_to_be64 (lt->_rkid));

    if (lt->tct) {
        if (!mutex_trylock (&ttp_global_root_head.event_mutx)) {
            return;
        }
        list_for_each_entry (ev, &lt->ncq, elm) {
            ttp_print_evt_val (seq, ev);
        }

        mutex_unlock (&ttp_global_root_head.event_mutx);
    }
}


TTP_NOTRACE
void ttpoe_parse_print (const struct sk_buff *skb, enum ttp_frame_direction dir, int lv)
{
    u16 etype;
    char *sdir;
    struct ttp_frame_hdr frh;
    struct ttp_pkt_info  pif = {0};

    if (ttp_verbose <= lv) {
        return;
    }

    etype = ttp_skb_pars (skb, &frh, &pif);
    switch (dir) {
    case TTP_RX:
        sdir = ">>>> RXQ";
        break;
    case TTP_TX:
        sdir = "<<<< TXQ";
        break;
    }

    TTP_VBG ("+---- Parse %s frame: (skb-len: %d) (noc-len: %d) ---+\n",
             sdir, skb->len, pif.noc_len);
    TTP_RAW ((u8 *)skb->data, skb->len);

    if (ttp_verbose > lv) {
        ttp_print_eth_hdr (frh.eth);
    }
    switch (etype) {
    case TESLA_ETH_P_TTPOE:
        ttp_print_tsla_type_hdr (frh.tth);
        ttp_print_shim_hdr (frh.tsh);
        break;
    case ETH_P_IP:
        ttp_print_ipv4_hdr (frh.ip4);
        ttp_print_shim_hdr (frh.tsh);
        break;
    case ETH_P_IPV6:
        ttp_print_ipv6_hdr (frh.ip6);
        ttp_print_shim_hdr (frh.tsh);
        break;
    default:
        return;
    }

    TTP_VBG ("Conn: opcode: %1d [ %s ]\n",
             frh.ttp->conn_opcode, TTP_OPCODE_NAME (frh.ttp->conn_opcode));

    TTP_VBG ("Conn:     vc: %-2d  tx: %-2d  rx: %-2d     epoch: %-2d\n",
             frh.ttp->conn_vc, frh.ttp->conn_tx, frh.ttp->conn_rx,
             ntohs (frh.ttp->conn_epoch));

    TTP_VBG ("Conn:  congn: %-2d    reserved: %*phC   extn: %-2d\n",
             frh.ttp->conn_congestion,
             (int)sizeof (frh.ttp->conn_reserved1), &frh.ttp->conn_reserved1,
             frh.ttp->conn_extension);

    TTP_VBG ("Conn: tx_seq: %-7u rx_seq: %-7u\n",
             ntohl (frh.ttp->conn_tx_seq), ntohl (frh.ttp->conn_rx_seq));

    if (pif.noc_len) {
        TTP_VBG (" NOC: tot-len: %zu\n", min ((size_t)pif.noc_len, sizeof (*frh.noc)));
        TTP_RAW ((u8 *)frh.noc, min ((size_t)pif.noc_len, sizeof (*frh.noc)));
    }
    if (pif.noc_len > sizeof (*frh.noc)) {
        TTP_VBG (" NOC: data-len: %d\n", pif.noc_len);
        TTP_RWS ((u8 *)frh.dat, pif.noc_len - sizeof (*frh.noc));
    }
}
