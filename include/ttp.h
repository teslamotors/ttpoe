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

/* Assigned to Tesla for TTPoE: Custom EtherType "0x9ac6" */
#define TESLA_ETH_P_TTPOE 0x9ac6

/* Assigned to Tesla for TTPoE: Custom MAC OUI "98-ED-5C" */
#define TESLA_MAC_OUI0    0x98
#define TESLA_MAC_OUI1    0xed
#define TESLA_MAC_OUI2    0x5c
#define TESLA_MAC_OUI     ((TESLA_MAC_OUI0<<16) | (TESLA_MAC_OUI1<<8) | TESLA_MAC_OUI2)

extern u8  Tesla_Mac_Oui0;
extern u8  Tesla_Mac_Oui1;
extern u8  Tesla_Mac_Oui2;
extern u32 Tesla_Mac_Oui; /* 3-bytes in host order: (mac[0]<<16)|(mac[1]<<8)|mac[2]) */

#define TTP_MIN_FRAME_LEN ((u16)64)   /* Ethernet minimum frame len */
#define TTP_MAX_FRAME_LEN ((u16)1536) /* Ethernet MAXimum frame len */

#define TTP_MAX_VCID      ((u8)2)     /* vc-id : [0, 1, 2] */

#define TTP_IPPROTO_TTP    146
#define TTP_TTH_MATCHES_IPH  1  /* set 0 for TTP w/o L3-gw: as implemented in FZ1 */

#define TTP_NOTRACE   notrace
#define TTP_NOINLINE  noinline
#define TTP_UNUSED    __maybe_unused

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
#  define TTP_DBG(a...)    printk (KERN_DEBUG   TTP_PREFIX a)
#  define TTP_LOG(a...)    printk (KERN_DEFAULT TTP_PREFIX a)
#  define TTP_VBG(aa...)   if (ttp_verbose >= 0) TTP_DBG (aa)
#endif

#ifndef from_work /* kernel-6.11.x defines this in include/linux/workqueue.h */
/* re-use trick from in timer.h to get to container struct for work context */
#  define from_work(var...)      from_timer(var)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)
#  define ttp_dev_read_lock()    rcu_read_lock ()
#  define ttp_dev_read_unlock()  rcu_read_unlock ()
#else
#  define ttp_dev_read_lock()    read_lock (&dev_base_lock)
#  define ttp_dev_read_unlock()  read_unlock (&dev_base_lock)
#endif

static inline struct class *ttp_wrap_class_create (const char *name)
{
    return class_create (
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
        THIS_MODULE,
#endif
        name);
}

static inline int ttp_dev_uevent (
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
    const
#endif
    struct device *dev, struct kobj_uevent_env *env)
{
    add_uevent_var (env, "DEVMODE=%#o", 0644);
    return 0;
}


#define TTP_XX2VAL(xx)       (isdigit (xx) ? (xx) - '0' :                    \
                              isxdigit (xx) ? toupper (xx) - 'A' + 0xA : 0)
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
# error "Neither Little-endian nor Big-endian"
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

/* Specify number of 32b long-words to pad: Selecting 4 gives 16B, combined with 4B of
 * TTH, gives us 20B in which to place an IPv4 header and replace TTP-Etype with IP */
#if   (TTP_TTH_MATCHES_IPH == 1)
#  define TTP_PROTO_PAD      (4)
#elif (TTP_TTH_MATCHES_IPH == 0)
#  define TTP_PROTO_PAD      (0)
#else
# error "Invalid TTP_TTH_MATCHES_IPH value"
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


/* len is number of bytes; returns true if !len or mem contains zeros as bytes */
static inline int ttp_mem_is_zero (const u8 *mem, int len)
{
    while (len > 0) {
        if (*(mem + (--len))) {
            return 0;
        }
    }
    return 1; /* is_zero? yes, all bytes zero */
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
     *  3. u8 b = ((b * 0x0802LU&0x22110LU) | (b * 0x8020LU&0x88440LU)) * 0x10101LU >> 16;
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
    if (!ttp_mem_is_zero (shim, ETH_ALEN/2)) {
        *((u32 *)mac) = htonl (Tesla_Mac_Oui << 8);
        memcpy (mac + 3, shim, ETH_ALEN/2);
    }
}


static inline void ttp_print_eth_hdr (const struct ethhdr *eth)
{
    if (ttp_verbose > 0) {
        TTP_DBG ("dmac: %*pM smac:%*pM etype:%04x\n", ETH_ALEN, eth->h_dest,
                 ETH_ALEN, eth->h_source, ntohs (eth->h_proto));
    }
}


static inline struct in6_addr *ttp_prefix_mac2ipv6 (struct in6_addr *ip,
                                                    u32 pre, const u8 *mac)
{
    ip->s6_addr32[0] = htonl (pre);
    addrconf_addr_eui48 ((u8 *)ip->s6_addr + 8, mac);
    return ip;
}


static inline struct in6_addr *ttp_mac2lla6 (struct in6_addr *ip, const u8 *mac)
{
    return ttp_prefix_mac2ipv6 (ip, 0xfe800000, mac);
}


static inline void ttp_print_ipv4_hdr (struct iphdr *ip)
{
    if (ttp_verbose > 0) {
        TTP_DBG ("ip4h: %*ph\n", 10, ip);
        TTP_DBG ("      %*ph\n", (int)sizeof (*ip) - 10, (10 + (u8 *)ip));
        TTP_DBG ("  ver:%d ihl:%d ttl:%d tos:%02x len:%d proto:%d%s\n",
                 ip->version, ip->ihl, ip->ttl, ip->tos, ntohs (ip->tot_len),
                 ip->protocol, ip->protocol == TTP_IPPROTO_TTP ? " (TTP)" : "");
        TTP_DBG (" dip4:%pI4 sip4:%pI4\n", &ip->daddr, &ip->saddr);
    }
}


static inline void ttp_print_ipv6_hdr (struct ipv6hdr *ipv6)
{
    if (ttp_verbose > 0) {
        TTP_DBG ("ip6h: %*ph\n", 20, ipv6);
        TTP_DBG ("      %*ph\n", (int)sizeof (*ipv6) - 20, (20 + (u8 *)ipv6));
        TTP_DBG ("  ver:%d len:%d ttl:%d proto:%d%s\n",
                 ipv6->version, ntohs (ipv6->payload_len), ipv6->hop_limit,
                 ipv6->nexthdr, ipv6->nexthdr == TTP_IPPROTO_TTP ? " (TTP)" : "");
        TTP_DBG (" dip6:%pI6c sip6:%pI6c\n", &ipv6->daddr, &ipv6->saddr);
    }
}


/*
 * Fills out ipv4 header in skb with gw-config given src-ip and dst-ip and
 * returns a pointer to the next header
 */
static inline u8 *ttp_prepare_ipv4 (u8 *pkt, int len, u32 sa4, u32 da4)
{
    u16 frame_len;
    struct iphdr *ipv4 = (struct iphdr *)pkt;

    frame_len = ETH_HLEN + sizeof (struct iphdr) + len;
    if (frame_len > TTP_MAX_FRAME_LEN) {
        return NULL;
    }
    frame_len = max (frame_len, TTP_MIN_FRAME_LEN);

    memset (ipv4, 0, sizeof (*ipv4));
    ipv4->version = 4;
    ipv4->ihl = 5;
    ipv4->ttl = 9;
    ipv4->protocol = TTP_IPPROTO_TTP;
    ipv4->saddr = sa4;
    ipv4->daddr = da4;
    ipv4->tot_len = htons (frame_len - ETH_HLEN);
    ipv4->check = ip_fast_csum ((unsigned char *)ipv4, ipv4->ihl);

    if (ttp_verbose > 2) {
        ttp_print_ipv4_hdr (ipv4);
    }

    return (u8 *)(ipv4 + 1);
}


/*
 * Fills out ipv6 header in skb with gw-config from src-ip and dst-ip and
 * returns a pointer to the next header
 */
static inline u8 *ttp_prepare_ipv6 (u8 *pkt, int len, const struct in6_addr *sa6,
                                    const struct in6_addr *da6)
{
    u16 frame_len;
    struct ipv6hdr *ipv6 = (struct ipv6hdr *)pkt;

    frame_len = ETH_HLEN + sizeof (struct ipv6hdr) + len;
    if (frame_len > TTP_MAX_FRAME_LEN) {
        return NULL;
    }
    frame_len = max (frame_len, TTP_MIN_FRAME_LEN);

    memset (ipv6, 0, sizeof (*ipv6));
    ipv6->version = 6;
    ipv6->nexthdr = TTP_IPPROTO_TTP;
    ipv6->hop_limit = 9;
    ipv6->saddr = *sa6;
    ipv6->daddr = *da6;
    ipv6->payload_len = htons (frame_len - ETH_HLEN - sizeof (struct ipv6hdr));

    if (ttp_verbose > 2) {
        ttp_print_ipv6_hdr (ipv6);
    }

    return (u8 *)(ipv6 + 1);
}


static inline void ttp_print_tsla_type_hdr (const struct ttp_tsla_type_hdr *tth)
{
    if (ttp_verbose > 0) {
        if (ttp_mem_is_zero ((u8 *)tth->pad, sizeof (tth->pad))) {
            TTP_DBG (" tth: subtyp:%d ver:%d tthl:%d gw:%d "
                     "res:0x%02x len:%d pad(%d)%s\n",
                     tth->styp, tth->vers, tth->tthl, tth->l3gw,
                     tth->resv, ntohs (tth->tot_len),
                     (int)sizeof (tth->pad),
                     (int)sizeof (tth->pad) ? ":00's" : "");
        } else {
            TTP_DBG (" tth: subtyp:%d ver:%d tthl:%d gw:%d "
                     "res:0x%02x len:%d\n",
                     tth->styp, tth->vers, tth->tthl, tth->l3gw,
                     tth->resv, ntohs (tth->tot_len));
            TTP_DBG ("      pad(%d): %*phN\n", (int)sizeof (tth->pad),
                     (int)sizeof (tth->pad), tth->pad);
        }
    }
}


static inline void ttp_print_shim_hdr (const struct ttp_tsla_shim_hdr *tsh)
{
    if (ttp_verbose > 0) {
        TTP_DBG (" tsh: src-node:%*phC dst-node:%*phC length:%d%s%*phC\n",
                 ETH_ALEN/2, tsh->src_node, ETH_ALEN/2, tsh->dst_node,
                 ntohs (tsh->length),
                 ntohs (tsh->length) == 2 ? " ctrl:" : "",
                 ntohs (tsh->length) == 2 ? 2 : 0, tsh + 1);
    }
}
#endif
