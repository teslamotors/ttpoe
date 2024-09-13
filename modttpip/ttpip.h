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


/* mapping of ttp-src-node / ttp-dst-node address in the 24b tesla shim header
 *  23 22 21 20 19 18 17 16 15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |    mac address [3]    |    mac address [4]    |    mac address [5]    |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
static inline void ttp_setup_shim_hdr (struct ttp_tsla_shim_hdr *tsh, const struct ethhdr *eth)
{
    memcpy (tsh->src_node, eth->h_source + 3, ETH_ALEN/2);
    memcpy (tsh->dst_node, eth->h_dest   + 3, ETH_ALEN/2);
}
**/


static const u8 ttp_debug_hv2zone_tbl[TTP_MAX_NUM_NODES] = {
    [0x00] = 0,
    [0x01] = 1,  [0x02] = 1,  [0x03] = 1,  [0x10] = 1,  [0xd3] = 1, // d1:11:8a
    [0x04] = 2,  [0x05] = 2,  [0x06] = 2,  [0x11] = 2,  [0x8d] = 2, // d1:10:54
    [0x07] = 3,  [0x08] = 3,  [0x09] = 3,               [0x4e] = 3, // d1:09:0f
    [0x0a] = 4,  [0x0b] = 4,  [0x0c] = 4,
    [0x0d] = 5,  [0x0e] = 5,  [0x0f] = 5,
    [0x21] = 6,  [0x22] = 6,  [0x23] = 6,  [0x24] = 6,
};

static inline u8 ttp_hash_from_shim (const u8 *shim)
{
    u8 mac[ETH_ALEN];

    ttp_mac_from_shim (mac, shim);
    return ttp_tag_index_hash_calc (mac);
}


static inline int ttp_zone_from_shim (const u8 *shim)
{
    u8 nid;

    nid = ttp_hash_from_shim (shim);
    if (nid >= TTP_MAX_NUM_NODES)
        return -EINVAL;

    return ttp_debug_hv2zone_tbl[nid];
}
