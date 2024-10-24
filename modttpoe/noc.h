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

#define TTP_NOC_DEBUG_PAGE_SIZE      (PAGE_SIZE - 96) /* 4000 = 4096 - 96 */
#define TTP_NOC_DEBUG_HDR_SIZE        8
#define TTP_NOC_DEBUG_PAYLOAD_SIZE   64

#define TTP_VC_ID__IS_VALID(vci)    (((vci) >= 0) && ((vci) <= TTP_MAX_VCID))

struct ttpoe_noc_host {
    u8 mac[ETH_ALEN]; /* source / target mac-address */
    u8 vc;            /* vc_id */
    u8 gw;            /* via l3-gateway */
    u8 ve;            /* valid entry */
};

extern struct ttpoe_noc_host ttp_debug_source, ttp_debug_target;

extern int ttpoe_noc_debug_rx (const u8 *data, const u16 nl);
extern int ttpoe_noc_debug_tx (u8 *buf, struct sk_buff *skb, const int nl,
                               const enum ttp_events_enum evnt,
                               struct ttpoe_noc_host *tg);
extern int ttpoe_noc_debug_tgt (u64 *kid, struct ttpoe_noc_host *tg);

extern int  __init ttpoe_noc_debug_init (void);
extern void __exit ttpoe_noc_debug_exit (void);
