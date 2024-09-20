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
 * TTP-GW      A sample implementation of Tesla Transport Protocol Gatewat (TTP-GW) that works with
 *             a network of Linux machines running the TTPoE kernel module and provides a way to
 *             allow islands of TTPoE in separate Layer-2 Ethernet networks to function seamlessly
 *             over an IPv4 network. This is work under development.
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

#define TESLA_ETH_P_TTPOE      0x9ac6 /* Custom EtherType for TTPoE: Assigned to Tesla */

/* MAC OUI 98:ed:5c - Assigned to Tesla */
#define TESLA_MAC_OUI0    0x98
#define TESLA_MAC_OUI1    0xed
#define TESLA_MAC_OUI2    0x5c
#define TESLA_MAC_OUI     ((TESLA_MAC_OUI0<<16)|(TESLA_MAC_OUI1<<8)|TESLA_MAC_OUI2)

/* MAC OUI 4c:fc:aa - Also assigned to Tesla */
#define TESLA_MAC2_OUI0   0x4c
#define TESLA_MAC2_OUI1   0xfc
#define TESLA_MAC2_OUI2   0xaa
#define TESLA_MAC2_OUI    ((TESLA_MAC2_OUI0<<16)|(TESLA_MAC2_OUI1<<8)|TESLA_MAC2_OUI2)

extern u8  Tesla_Mac_Oui0;
extern u8  Tesla_Mac_Oui1;
extern u8  Tesla_Mac_Oui2;
extern u32 Tesla_Mac_Oui;

#define TTP_MIN_FRAME_LEN ((u16)64)   /* Ethernet minimum frame len */
#define TTP_MAX_FRAME_LEN ((u16)1536) /* Ethernet MAXimum frame len */

#define TTP_MAX_VCID      ((u8)2)     /* vc-id : [0, 1, 2] */

#define IPPROTO_TTP        146
#define TTP_TTH_MATCHES_IPH  1  /* set 0 for TTP w/o L3-gw: as implemented in FZ1 */

#define TTP_NOTRACE   notrace
#define TTP_NOINLINE  noinline
#define TTP_UNUSED    __attribute__((unused))

#define CLEAR    "\e[00m"
#define GRAY     "\e[30m"
#define RED      "\e[31m"
#define GREEN    "\e[32m"
#define YELLOW   "\e[33m"
#define BLUE     "\e[34m"
#define MAGENTA  "\e[35m"
#define CYAN     "\e[36m"
#define WHITE    "\e[37m"
#define NOCOLOR  ""

#ifdef __KERNEL__
#define TTP_DBG(a...)  printk (KERN_DEBUG   TTP_PREFIX a)
#define TTP_LOG(a...)  printk (KERN_DEFAULT TTP_PREFIX a)
#define TTP_VBG(aa...) if (ttp_verbose >= 0) TTP_DBG (aa)
#endif

/* re-use the trick used in timers to get to container struct for the work context */
#define from_work(var...) from_timer(var)

#define TTP_XX2VAL(xx)       (isdigit (xx) ? (xx) - '0' : isxdigit (xx) ? toupper (xx) - 'A' + 0xA : 0)
#define TTP_HEX2BY(cx,cy)    ((16 * TTP_XX2VAL (cx)) + TTP_XX2VAL (cy))
#define TTP_NAH2B(n,a,x,y)   ((16 * TTP_XX2VAL ((n) > (x) ? (a)[(x)] : 0)) + \
                              TTP_XX2VAL ((n) > (y) ? (a)[(y)] : 0))

extern int ttp_verbose;
extern int ttp_shutdown;
extern char *ttp_dev;


/* Tesla Type Header (TTH) that follows Tesla Ethertype in MAC header
 *
 *  15  14  13  12  11  10   9   8   7   6   5   4   3   2   1   0
 * +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+ -^-
 * |  styp |  vers |   tthl [3:0]  | gw|       reserved [7:0]      |  |
 * +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+ 1x32bit
 * |                      total-length [15:0]                      |  |
 * +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+ -X-
 * |                                                               |  |
 * |                                                               |  |
 * ~                       padding (4x32bit)                       ~ 4x32bit
 * |                                                               |  |
 * |                                                               |  |
 * +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+ -v-
 */
struct ttp_tsla_type_hdr {
    struct {
#if defined (__LITTLE_ENDIAN_BITFIELD)
        u8 tthl : 4;            /* similar to ip.ihl */
        u8 vers : 2;
        u8 styp : 2;
#elif defined (__BIG_ENDIAN_BITFIELD)
        u8 vers : 2;
        u8 styp : 2;
        u8 tthl : 4;
#elif defined (__KERNEL__)
#error "Neither Little-endian nor Big-endian"
#else
        u8 tthl : 4;            /* similar to ip.ihl */
        u8 vers : 2;
        u8 styp : 2;
#endif

#if defined (__LITTLE_ENDIAN_BITFIELD)
        u8 resv : 7;
        u8 l3gw : 1;
#else /* (__BIG_ENDIAN_BITFIELD) */
        u8 l3gw : 1;
        u8 resv : 7;
#endif
    } __attribute__((packed));
    u16 tot_len;                /* similar to ip.tot_len */

#if   (TTP_TTH_MATCHES_IPH == 1)
#define TTP_PROTO_PAD           (4)
#elif (TTP_TTH_MATCHES_IPH == 0)
#define TTP_PROTO_PAD           (0)
#else
#error "Invalid TTP_TTH_MATCHES_IPH value"
#endif

#define TTP_PROTO_TTHL          (1 + TTP_PROTO_PAD)
    u32 pad[TTP_PROTO_PAD];     /* pad to make TTH overlap IPH */
} __attribute__((packed));


/* Shim Header (TSH) that follows TTH in L2-format, and IPH in L3-format
 *
 *  15  14  13  12  11  10   9   8   7   6   5   4   3   2   1   0
 * +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 * |                        src_node [23:8]                        |
 * + -   -   -   -   -   -   -   - +---+---+---+---+---+---+---+---+
 * |         src_node [7:0]        |        dst_node [23:16]       |
 * +---+---+---+---+---+---+---+---+ -   -   -   -   -   -   -   - +
 * |                        dst_node [15:0]                        |
 * +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 * |                          length [15:0]                        |
 * +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 */
struct ttp_tsla_shim_hdr {
    u8  src_node[ETH_ALEN/2];
    u8  dst_node[ETH_ALEN/2];
    u16 length;
} __attribute__((packed));


#define TTP_LITTLE_XTRA     8   /* needed to avoid hitting skb kernel panic */
#define TTP_IP_HEADROOM    (ETH_HLEN + sizeof (struct in6_addr) + TTP_LITTLE_XTRA)


/* len is number of u32 words; returns true if !len or mem contains zeros as 32b chunks */
static inline int ttp_mem_is_zero (const u8 *mem, int len)
{
    while (len > 0) {
        if (*((const u32 *)mem + (--len))) {
            return 0;
        }
    }

    return 1;
}


static inline u8 ttp_tag_reverse_bits (u8 in)
{
    u8 out = in;

    if (0 == in || 0xff == in) {
        return in;
    }

    out = (((out & 0xaa) >> 1) & 0x55) | (((out & 0x55) << 1) & 0xaa);
    out = (((out & 0xcc) >> 2) & 0x33) | (((out & 0x33) << 2) & 0xcc);
    out = (((out & 0xf0) >> 4) & 0x0f) | (((out & 0x0f) << 4) & 0xf0);

    return out;

    /* Other clever methods from http://graphics.stanford.edu/~seander/bithacks.html
     *  1. u8 b = ((b * 0x0202020202ULL & 0x010884422010ULL) % 1023) & 0xff;
     *  2. u8 b = ((b * 0x80200802ULL) & 0x0884422110ULL) * 0x0101010101ULL >> 32;
     *  3. u8 b = ((b * 0x0802LU & 0x22110LU) | (b * 0x8020LU & 0x88440LU)) * 0x10101LU >> 16;
     */
}


static inline u8 ttp_tag_index_hash_calc (const u8 *mac)
{
    return (mac[3] ^ ttp_tag_reverse_bits (mac[4]) ^ mac[5]) & 0xff;
}


#ifdef __KERNEL__
/* mapping of ttp-src-node / ttp-dst-node address in the 24b tesla shim header
 *  23 22 21 20 19 18 17 16 15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |    mac address [3]    |    mac address [4]    |    mac address [5]    |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
static inline void ttp_mac_from_shim (u8 *mac, const u8 *shim)
{
    *((u32 *)mac) = ntohl (Tesla_Mac_Oui << 8);
    memcpy (mac + 3, shim, ETH_ALEN/2);
}


static inline void ttp_print_eth_hdr (struct ethhdr *eth)
{
    if (ttp_verbose) {
        TTP_DBG ("dmac: %*pM smac:%*pM etype:%04x\n", ETH_ALEN, eth->h_dest,
                 ETH_ALEN, eth->h_source, ntohs (eth->h_proto));
    }
}


static inline void ttp_print_tsla_type_hdr (struct ttp_tsla_type_hdr *tth)
{
    if (ttp_verbose) {
        if (ttp_mem_is_zero ((u8 *)tth->pad, ((int)sizeof (tth->pad)) / 4)) {
            TTP_DBG (" tth: subtyp:%d ver:%d tthl:%d gw:%d res:0x%02x len:%d pad(%d)%s\n",
                     tth->styp, tth->vers, tth->tthl, tth->l3gw, tth->resv, ntohs (tth->tot_len),
                     (int)sizeof (tth->pad), (int)sizeof (tth->pad) ? ":00's" : "");
        } else {
            TTP_DBG (" tth: subtyp:%d ver:%d tthl:%d gw:%d res:0x%02x len:%d\n",
                     tth->styp, tth->vers, tth->tthl, tth->l3gw, tth->resv, ntohs (tth->tot_len));
            TTP_DBG ("      pad(%d): %*phN\n", (int)sizeof (tth->pad), (int)sizeof (tth->pad), tth->pad);
        }
    }
}


static inline void ttp_print_shim_hdr (struct ttp_tsla_shim_hdr *tsh)
{
    if (ttp_verbose) {
        TTP_DBG (" tsh: src-node:%*phC dst-node:%*phC length:%d\n", ETH_ALEN/2,
                 tsh->src_node, ETH_ALEN/2, tsh->dst_node, ntohs (tsh->length));
    }
}
#endif
