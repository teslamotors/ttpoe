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

#define TTP_EVENTS_POOL_SIZE 1024 /* handle 2x512 tags */

struct ttp_fsm_evlog {
    struct list_head       lm;

    enum ttp_states_enum   cs;
    enum ttp_events_enum   ev;
    enum ttp_response_enum rs;
    enum ttp_states_enum   ns;

    enum ttp_opcodes_enum  op;

    u8  hv;
    u8  bk;
    u8  vc;

    int ps;

    u32 rx;
    u32 tx;
    u16 sz;

    u64 kd;
    u64 ts;
    u32 ix;
    u32 rf;

    u8 *fl;                     /* __FILE__ */
    u8 *fn;                     /* __FUNCTION__ */
    u32 ln;                     /* __LINE__ */
} __attribute__((packed));


struct ttp_fsm_event {
    struct list_head      elm;
    enum ttp_events_enum  evt;

    u32                   idx;
    u32                   mrk;

    u64                   kid;

    struct ttp_pkt_info   psi;
    struct sk_buff       *rsk;
    struct sk_buff       *tsk;
} __attribute__((packed));


struct ttp_link_tag_global {
    struct sk_buff_head  skb_head;

    struct list_head     pool_head;

    struct list_head     rxq_head;
    struct list_head     txq_head;
    struct list_head     akq_head;
    struct list_head     inq_head;

    struct rb_root       tag_rbroot;

    struct timer_list    timer_head;
    struct work_struct   work_queue;

    spinlock_t           spin_lock;
    struct mutex         event_mutx;

    struct list_head     evlog_head;
    struct mutex         evlog_mutx;

    struct ttp_fsm_event event_arr[TTP_EVENTS_POOL_SIZE];
    struct ttp_fsm_evlog evlog_arr[TTP_EVENTS_POOL_SIZE];
};

extern struct ttp_link_tag_global ttp_global_root_head;

#define TTP_RUN_SPIN_LOCKED(_locked_code...)                \
    {                                                       \
        unsigned long _flg;                                 \
        spinlock_t *_spl = &ttp_global_root_head.spin_lock; \
        spin_lock_irqsave (_spl, _flg); {                   \
            _locked_code;                                   \
        } spin_unlock_irqrestore (_spl, _flg);              \
    }

#define TTP_EVENTS_INDX_OF(ev)  ((int)((ev) - ttp_global_root_head.event_arr))
#define TTP_EV_LOG_INDX_OF(lg)  ((int)((lg) - ttp_global_root_head.evlog_arr))

#define TTP_EVENTS_STR_TO_FENCE(ss)                                \
    ({                                                             \
        int _ff = (ss[0]<<24) + (ss[1]<<16) + (ss[2]<< 8) + ss[3]; \
        _ff;                                                       \
    })

#define TTP_EVENTS_FENCE_TO_STR(ff)                      \
    ({                                                   \
        static u8 _ss[5] = "none";                       \
        if ((ff)) {                                      \
            _ss[0] = (((ff) & 0xff000000) >> 24) & 0xff; \
            _ss[1] = (((ff) & 0x00ff0ff0) >> 16) & 0xff; \
            _ss[2] = (((ff) & 0x0000ff00) >>  8) & 0xff; \
            _ss[3] = (((ff) & 0x000000ff))       & 0xff; \
            _ss[4] = '\0';                               \
        }                                                \
        _ss;                                             \
    })

/* Trip-wire fence markers */
#define TTP_EVENTS_FENCE_FREE_ELEM  TTP_EVENTS_STR_TO_FENCE("free") /* item is totally free */
#define TTP_EVENTS_FENCE_POOL_ELEM  TTP_EVENTS_STR_TO_FENCE("pool") /* item in free pool */
#define TTP_EVENTS_FENCE_TX_Q_ELEM  TTP_EVENTS_STR_TO_FENCE("tx_q") /* item in noc tx queue */
#define TTP_EVENTS_FENCE_RX_Q_ELEM  TTP_EVENTS_STR_TO_FENCE("rx_q") /* item in event rx-queue */
#define TTP_EVENTS_FENCE_AK_Q_ELEM  TTP_EVENTS_STR_TO_FENCE("ak_q") /* item in event ack-queue */
#define TTP_EVENTS_FENCE_IN_Q_ELEM  TTP_EVENTS_STR_TO_FENCE("in_q") /* item in event int-queue */
#define TTP_EVENTS_FENCE__NOC_ELEM  TTP_EVENTS_STR_TO_FENCE("_noc") /* item from noc interface */
#define TTP_EVENTS_FENCE__CTL_ELEM  TTP_EVENTS_STR_TO_FENCE("_ctl") /* item from ctl interface */
#define TTP_EVENTS_FENCE__DBG_ELEM  TTP_EVENTS_STR_TO_FENCE("_dbg") /* item from dbug interface*/
#define TTP_EVENTS_FENCE_EXPT_ELEM  TTP_EVENTS_STR_TO_FENCE("expt") /* item for experimenting */

#define TTP_TAG_TBL_SIZE     256
#define TTP_TAG_TBL_BKTS_NUM 2
#if    (TTP_TAG_TBL_BKTS_NUM != 2)
#error "Tag table requires number of buckets to be exactly 2"
#endif

#define TTP_TMX_GWMAC_ADV_VAL     2000
#define TTP_TMX_OPEN_SENT_VAL     1150
#define TTP_TMX_PAYLOAD_SENT_VAL  1300
#define TTP_TMX_CLOSE_SENT_VAL    1300
#define TTP_TMX_PAYLOAD2_SENT_VAL 1500


/* Tag value of a single 148b tag entry */
struct ttp_link_tag {
    struct timer_list  tmr;
    struct work_struct wkq;
    struct rb_node     rbn;

    struct list_head   ncq;     /* noc queue */

    bool               tex;     /* timer expired */

    u16                twz;     /* tx window size (defaults to 1 for now) */
    u16                tct;     /* tx-queue count */
    u16                txt;     /* tx-scheduled count */
    u16                try;     /* tx-retry count */

    u8  valid;                  /* tag valid */
    u8  state;                  /* 3b state[2:0] in HW (in SW use enum ttp_states_enum) */

    u8  retire_ptr;
    u8  current_ptr;
    u8  alloc_ptr;

    u32 rx_seq_id;
    u32 tx_seq_id;
    u32 retire_id;

    atomic_t opens;

    union {
        struct {
            union {
                struct {
                    u8  vci :2; /* vc-id: [0, 1, or 2] */
                    u8  _xx :5; /* reserved0 */
                    u8  _z0 :1; /* must be ZERO */

                    u8  mac[ETH_ALEN/2]; /* 24b MAC */
                } __attribute__((packed));
                u32 _rkey;      /* raw key used in rb-tree ops */
            };

            union {
                struct {
                    u8  _y1;    /* reserved0 */

                    u8  oct :3; /* octant */
                    u8  _rs :1; /* reserved0 */
                    u8  rng :4; /* ring */

                    u8  gwy :1; /* destimation reachable via gateway */
                    u8  bkt :1; /* hash bucket */
                    u8  _y2 :6; /* reserved0 */

                    u8  hvl;    /* hash value */
                } __attribute__((packed));
                u32 _rval;      /* raw tag value - NOT used in rb-tree ops */
            };
        } __attribute__((packed));

        u64    _rkid;           /* raw 64 bit kid */
    } __attribute__((packed));
};


#define TTP_BLOOM_SIZE_BITS  10
#if (TTP_BLOOM_SIZE_BITS > 16 || TTP_BLOOM_SIZE_BITS < 8)
#error "Bloom filter only designed to have 8 - 16 bits"
#endif

#define TTP_BLOOM_SIZE        (1 << TTP_BLOOM_SIZE_BITS)
#define TTP_BLOOM_MASK       ((1 << TTP_BLOOM_SIZE_BITS) - 1)
#define TTP_BLOOM_SIZEOF     (sizeof (ttp_bloom_bitmap) / sizeof (unsigned long))

/* bloom filter for checking kid */
extern unsigned long ttp_bloom_bitmap[];

extern void   ttp_bloom_add (u64 kid);
extern int    ttp_bloom_test (u64 kid);

extern void ttp_rbtree_tag_add (struct ttp_link_tag *tag);
extern void ttp_rbtree_tag_del (u64 kid);
extern struct ttp_link_tag *ttp_rbtree_tag_get (u64 kid);

struct ttp_stats_all {
    atomic_t adds[TTP_TAG_TBL_BKTS_NUM]; /* counter per bucket 0/1 */
    atomic_t dels[TTP_TAG_TBL_BKTS_NUM];
    atomic_t coll[TTP_TAG_TBL_SIZE];     /* hash collisions per hash value */
    atomic_t colls;                      /* total hash collisions */

    u16  pool;
    u16  queue;
    u16  timer;
    u16  nocq;
    u16  evlog;

    u32  ovr_fl;
    u32  und_fl;

    u32  err_ev;
    u32  err_lg;

    atomic_t skb_ct;
    atomic_t skb_rx;
    atomic_t skb_tx;

    atomic_t frm_ct;
    atomic_t pld_ct;
    atomic_t drp_ct;

    u16  wkq_st;
    u16  wkq_sz;
};


extern struct ttp_stats_all ttp_stats;

/* separate link-tag tables for each vci: [0, 1, 2] */
extern struct ttp_link_tag ttp_link_tag_tbl_0[TTP_TAG_TBL_SIZE][TTP_TAG_TBL_BKTS_NUM];
extern struct ttp_link_tag ttp_link_tag_tbl_1[TTP_TAG_TBL_SIZE][TTP_TAG_TBL_BKTS_NUM];
extern struct ttp_link_tag ttp_link_tag_tbl_2[TTP_TAG_TBL_SIZE][TTP_TAG_TBL_BKTS_NUM];

extern struct ttp_fsm_state_var ttp_fsm_table[TTP_EV__NUM_EV][TTP_ST__NUM_ST];
extern ttp_fsm_fn ttp_fsm_entry_function[];


extern void ttp_fsm_init (void);
extern void ttp_fsm_exit (void);
extern void ttp_gwmacadv (void);
extern u64  ttp_tag_key_make (const u8 *mac, u8 vc, u8 gw);

extern int  ttp_tag_add (u64 kid);
extern void ttp_tag_reset (struct ttp_link_tag *lt);

extern void ttp_fsm_evlog_add (const char *fl, const int ln, const char *fn, const int pos,
                               struct ttp_fsm_event *qev, enum ttp_events_enum evn,
                               enum ttp_opcodes_enum op, struct ttp_pkt_info *pif);

#define _TTP_EVLOG(ar...)      ttp_fsm_evlog_add(__FILE__,__LINE__,__FUNCTION__,__COUNTER__, ar)
#define TTP_EVLOG(ev,en,op)   _TTP_EVLOG(ev, en, op, ev?&(((struct ttp_fsm_event *)ev)->psi):NULL)

extern void ttp_noc_requ (struct ttp_link_tag *lt);
extern int  ttp_noc_dequ (struct ttp_link_tag *lt);

extern void ttp_noc_enqu (struct ttp_fsm_event *ev);
extern void ttp_evt_pput (struct ttp_fsm_event *ev);
extern void ttp_evt_enqu (struct ttp_fsm_event *ev);

extern void ttp_evt_cpqu (struct ttp_fsm_event *ev);
extern bool ttp_evt_pget (struct ttp_fsm_event **evp);
