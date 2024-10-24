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

#define TTP_MAX_NUM_NODES      256
#define TTP_MAX_NODE_MASK     (TTP_MAX_NUM_NODES -1)
#if (TTP_MAX_NODE_MASK & (TTP_MAX_NUM_NODES))
#error "Error: TTP_MAX_NUM_NODES is not a power of 2"
#endif

#define TTP_MAX_NUM_ZONES        8
#define TTP_MAX_ZONE_MASK     (TTP_MAX_NUM_ZONES -1)
#if (TTP_MAX_ZONE_MASK & (TTP_MAX_NUM_ZONES))
#error "Error: TTP_MAX_NUM_ZONES is not a power of 2"
#endif

#define TTP_MAX_NUM_INTFS       20

#define TTP_NH_MAC_TRY_TMR    1000 /* msec */
#define TTP_GW_CTL_ADV_TMR    1000 /* msec */
#define TTP_MAC_TABLE_SIZE     256
#define TTP_U32_MAX_MAX_VAL   ((1U << 32) - 1)

/* +----- Aging algorithm: R=remote N=new -----+
 * | -1    0   1   2  . . .  | OLD         MAX |
 * +----+----+---+---+...+---+----+---+...+----+
 * |  R |  N |<--- Alive --->|<-- Old --->|Dead|
 * +----+----+---+---+...+---+----+---+...+----+
 */
#define TTP_MAC_AGEOUT_MAX      60 /* N sec; Num ticks @TTP_GW_CTL_ADV_TMR(ms)/tick */
#if    (TTP_MAC_AGEOUT_MAX >= TTP_U32_MAX_MAX_VAL)
#error "TTP_MAC_AGEOUT_MAX overflows maximum value for 16 bits"
#endif
#define TTP_MAC_AGE_OLD_PC      50 /* as % of MAX */
#define TTP_MAC_AGEOUT_OLD    (TTP_MAC_AGEOUT_MAX * TTP_MAC_AGE_OLD_PC / 100)

enum ttp_mac_opcodes {
    TTP_GW_CTL_OP_LOCAL_ADD   = 0,
    TTP_GW_CTL_OP_LOCAL_DEL   = 1, /* unused: relies on aging */

    TTP_GW_CTL_OP_NODE_ADD    = 2, /* unused: relies on node's reply to gw-mac-adv */
    TTP_GW_CTL_OP_NODE_DEL    = 3, /* unused: relies on aging */

    TTP_GW_CTL_OP_REMOTE_ADD  = 4,
    TTP_GW_CTL_OP_REMOTE_DEL  = 5,

    TTP_GW_CTL_OP_GATEWAY_ADD = 6,
    TTP_GW_CTL_OP_GATEWAY_SLF = 7,

    TTP_GW_CTL_OP_RESERVED1   = 8, /* reserved */
    TTP_GW_CTL_OP_RESERVED2   = 9, /* reserved */

    TTP_GW_CTL_OP_INVALID     = 10,/* tombstone */
};

struct ttp_timer {
    const int         max; /* max number or tries */
    const int         exp; /* expiry in millisec */
    bool              rst; /* set true to force reset; one shot: true -> false */
    int               try; /* count of number or tries: cleared on force reset */
    struct timer_list tmh;
};
extern struct ttp_timer ttp_nh_mac_tmr;
extern struct ttp_timer ttp_gw_ctl_tmr;

struct ttp_mactable {
    int zon;
    int age;
    u8  mac[ETH_ALEN];

    union { /* flags */
        struct {
            u8 vld : 1;
            u8 rem : 1;
            u8 gwf : 1;
            u8 prm : 1;
            u8 _x_ : 4;
        };
        u8     flg;
    };
    struct { /* stats */
        u64 byt;
        u32 frm;
    } r,t;

    struct rb_node rbn;
};

struct ttp_intf_cfg {
    int  zon;
    int  ver; /* 4 or 6, anything else = invalid */
    int  pfl; /* prefix len */
    bool gwy; /* uses gateway */
    u8   mac[ETH_ALEN];

    union {
        struct in_addr  da4;
        struct in6_addr da6;
    };
    union {
        struct in_addr  sa4;
        struct in6_addr sa6;
    };

    const struct net_device *dev;
};
extern struct ttp_intf_cfg ttp_zones[TTP_MAX_NUM_ZONES];

extern struct mutex   ttp_mactbl_mutx;
extern struct mutex   ttp_zoncfg_mutx;
extern struct rb_root ttp_mactbl_rbroot;
