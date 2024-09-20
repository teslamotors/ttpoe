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

#define TTP_MAX_NUM_NODES      256
#define TTP_MAX_NODE_MASK     (TTP_MAX_NUM_NODES -1)
#if (TTP_MAX_NODE_MASK & (TTP_MAX_NUM_NODES))
#error "Error: TTP_MAX_NUM_NODES is not a power of 2"
#endif

#define TTP_MAX_NUM_ZONES      8
#define TTP_MAX_ZONE_MASK     (TTP_MAX_NUM_ZONES -1)
#if (TTP_MAX_ZONE_MASK & (TTP_MAX_NUM_ZONES))
#error "Error: TTP_MAX_NUM_ZONES is not a power of 2"
#endif

#define TTP_MAX_NUM_EDEVS       20
#define TTP_MAX_NUM_INTFS       20

#define TTP_GW_MAC_ADV_TMR 1000 /* msec */
#define TTP_MAC_TABLE_SIZE  256
#define TTP_U8_MAX_MAX_VAL  255

/* +----- Aging algorithm: R=remote N=new -----+
 * | -1    0   1   2  . . .  | OLD         MAX |
 * +----+----+---+---+...+---+----+---+...+----+
 * |  R |  N |<--- Alive --->|<-- Old --->|Dead|
 * +----+----+---+---+...+---+----+---+...+----+
 */
#define TTP_MAC_AGEOUT_MAX   30 /* Nx MAC_ADV_TMR ex: 30 sec @1s tick */
#if    (TTP_MAC_AGEOUT_MAX >= TTP_U8_MAX_MAX_VAL)
#error "TTP_MAC_AGEOUT_MAX overflows maximum value for 8 bits"
#endif
#define TTP_MAC_AGEOUT_OLD   (TTP_MAC_AGEOUT_MAX * 80 / 100) /* 80% of MAX */

enum ttp_mac_opcodes {
    TTP_LOCAL,
    TTP_GATEWAY,
    TTP_REMOTE_ADD,
    TTP_REMOTE_DEL,
    TTP_INVALID,
};

struct ttp_mactable {
    struct rb_node rbn;
    union { /* flags */
        struct {
            u8     val : 1;
            u8     rem : 1;
            u8     gwf : 1;
            u8     _x_ : 5;
        };
        u8         flg;
    };
    u8             zon;
    s8             age;
    u8             mac[ETH_ALEN];
};

struct ttp_intf_cfg {
    u8                  zon;
    u8                  ver;
    union {
        struct in_addr  ip4;
        struct in6_addr ip6;
    };
    u8                  pfl; /* prefix len */
    u8                  gwy; /* uses gateway */
    struct net_device  *dev;
    u8                  mac[ETH_ALEN];
};
extern struct ttp_intf_cfg ttp_zones[TTP_MAX_NUM_ZONES];
extern struct ttp_intf_cfg ttp_edevs[TTP_MAX_NUM_EDEVS];
extern struct ttp_intf_cfg ttp_intfs[TTP_MAX_NUM_INTFS];

extern struct mutex   ttp_mactable_mutx;
extern struct rb_root ttp_mactbl_rbroot;
