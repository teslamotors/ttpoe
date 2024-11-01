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

#ifndef MODULE
#define MODULE
#endif

#ifndef __KERNEL__
#define __KERNEL__
#endif

#include <linux/skbuff.h>
#include <linux/version.h>
#include <linux/netdevice.h>
#include <linux/types.h>
#include <linux/bitops.h>
#include <linux/cred.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/timer.h>
#include <linux/crc16.h>
#include <net/addrconf.h>

#include <ttp.h>

#include "ttpoe.h"
#include "fsm.h"
#include "tags.h"
#include "print.h"
#include "noc.h"


struct ttp_link_tag_global ttp_global_root_head;

struct ttp_link_tag  ttp_link_tag_tbl_0[TTP_TAG_TBL_SIZE][TTP_TAG_TBL_BKTS_NUM];
struct ttp_link_tag  ttp_link_tag_tbl_1[TTP_TAG_TBL_SIZE][TTP_TAG_TBL_BKTS_NUM];
struct ttp_link_tag  ttp_link_tag_tbl_2[TTP_TAG_TBL_SIZE][TTP_TAG_TBL_BKTS_NUM];

struct ttp_stats_all ttp_stats;

int ttp_tag_seq_init_val = 1; /* can be any value (try: test with other values) */

TTP_NOTRACE
static u8 ttp_tag_index_hash_get (u64 kid)
{
    struct ttp_link_tag lt;

    lt._rkid = kid;
    return lt.hvl;
}


TTP_NOTRACE
static u8 ttp_tag_index_vci_get (u64 kid)
{
    struct ttp_link_tag lt;

    lt._rkid = kid;
    return lt.vci;
}


TTP_NOTRACE
static u8 ttp_tag_index_gw3_get (u64 kid)
{
    struct ttp_link_tag lt;

    lt._rkid = kid;
    return lt.gw3;
}


TTP_NOTRACE
static u8 ttp_tag_index_tp4_get (u64 kid)
{
    struct ttp_link_tag lt;

    lt._rkid = kid;
    return lt.tp4;
}


/*
 * Init sw-link-tag with a fully-associative raw 64b kid. This indexes a globally unique
 * ttp end-point. The u8 hash-value is also stored. The 256-entry 2-way hash-table is a
 * cache for the fully-associative sw-link-tag table. The tag is 'invalid' at init.
 */
u64 ttp_tag_key_make (const u8 *mac, u8 vc, bool gw, bool t4)
{
    struct ttp_link_tag lt;

    lt._rkid = 0ULL;            /* clear just the raw tag bits */

    if (!mac || !TTP_VC_ID__IS_VALID (vc)) {
        return lt._rkid;        /* 0ULL tag (kid) is invalid */
    }

    lt.hvl = ttp_tag_index_hash_calc (mac);

    lt.vci = vc;
    lt.gw3 = gw;
    lt.tp4 = t4;

    lt.mac[0] = mac[3];
    lt.mac[1] = mac[4];
    lt.mac[2] = mac[5];

    lt.bkt = 0;

    lt.rng = 0;
    lt.oct = 0;

    return lt._rkid;
}


TTP_NOINLINE
static void ttp_tag_signal_tag (struct ttp_fsm_event *ev)
{
    struct ttp_link_tag *lt;

    if (TTP_EV__TXQ__TTP_PAYLOAD != ev->evt) {
        return;
    }
    if ((lt = ttp_rbtree_tag_get (ev->kid)) && lt->txt) {
        lt->txt--;
    }
}


TTP_NOINLINE
static enum ttp_states_enum ttp_tag_get_state (u64 kid)
{
    struct ttp_link_tag *lt;

    if (kid && (lt = ttp_rbtree_tag_get (kid))) {
        return lt->state;
    }
    return TTP_ST__CLOSED;
}


TTP_NOINLINE
void ttp_tag_reset (struct ttp_link_tag *lt)
{
    lt->valid       = 0;
    lt->state       = TTP_ST__CLOSED;

    lt->retire_ptr  = 0;
    lt->current_ptr = 0;
    lt->alloc_ptr   = 0;

    lt->tx_seq_id   = 0;
    lt->rx_seq_id   = 0;
    lt->retire_id   = 0;

    lt->tex = false;    /* timer expired */
    lt->twz = 1;        /* default window size (defaults to 1 for now) */
    lt->tct = 0;        /* tx-queue count */
    lt->txt = 0;        /* tx-scheduled count */
    lt->try = 0;        /* tx-retry count */

    lt->_rkid = 0ULL;   /* clear whole raw key id */
}


/* add 'tag' to table: return 0 (hash val in kid); 1 if both bkts are full*/
int ttp_tag_add (u64 kid)
{
    u8  vc, gw, hv, t4;
    int bk;
    struct ttp_link_tag *lt;

    if ((lt = ttp_rbtree_tag_get (kid))) {
        return 0;
    }

    hv = ttp_tag_index_hash_get (kid);
    vc = ttp_tag_index_vci_get (kid);
    gw = ttp_tag_index_gw3_get (kid);
    t4 = ttp_tag_index_tp4_get (kid);

    if (vc == 0) {
        lt = ttp_link_tag_tbl_0[hv];
    }
    else if (vc == 1) {
        lt = ttp_link_tag_tbl_1[hv];
    }
    else if (vc == 2) {
        lt = ttp_link_tag_tbl_2[hv];
    }
    else {
        BUG_ON (1);
    }

    /* try bkt-0 first then bkt-1 */
    for (bk = 0; bk < 2; bk++) {
        if (!lt->valid) { /* found an empty slot */
            lt->valid = 1;
            lt->state = TTP_ST__CLOSED;

            lt->_rkid = kid;
            ttp_rbtree_tag_add (lt);

            lt->bkt = bk;
            lt->gw3 = gw;
            lt->tp4 = t4;
            lt->hvl = hv;

            lt->retire_id = ttp_tag_seq_init_val;
            lt->rx_seq_id = ttp_tag_seq_init_val;
            lt->tx_seq_id = ttp_tag_seq_init_val + 1; /* TTP_OPEN: init-val, use next */

            atomic_inc (&ttp_stats.adds[bk]);
            return 0;
        }

        lt++;  /* next bkt */
    }

    atomic_inc (&ttp_stats.coll[hv]);
    atomic_inc (&ttp_stats.colls);

    return 1; /* both 'ways' (bkts) full; victimize (TODO) */
}


TTP_NOINLINE
static void ttp_fsm_lookup_state_table (u64 kid, enum ttp_events_enum evn,
                                        enum ttp_states_enum *cs,
                                        enum ttp_states_enum *ns,
                                        enum ttp_response_enum *rs)
{
    *cs = ttp_tag_get_state (kid);
    *ns = ttp_fsm_table[evn][*cs].next_state;
    *rs = ttp_fsm_table[evn][*cs].response;
}


TTP_NOINLINE
void ttp_fsm_evlog_add (const char *fil, const int lin,
                        const char *fun, const int pos,
                        struct ttp_fsm_event *qev, enum ttp_events_enum evn,
                        enum ttp_opcodes_enum opc, struct ttp_pkt_info *pif)
{
    struct ttp_link_tag *lt;
    struct ttp_fsm_evlog *lg;

    BUG_ON (qev && qev->tsk && qev->rsk);

    if (!mutex_trylock (&ttp_global_root_head.evlog_mutx)) {
        TTP_LOG ("%s: trylock failed, logev: %d\n", __FUNCTION__, evn);
        return;
    }

    lg = list_first_entry (&ttp_global_root_head.evlog_head, struct ttp_fsm_evlog, lm);
    if (!lg) {
        mutex_unlock (&ttp_global_root_head.evlog_mutx);
        return;
    }

    list_del (&lg->lm);

    lg->ps = pos;
    lg->ts = jiffies;
    lg->ev = evn;
    lg->op = opc;
    lg->kd = qev ? qev->kid : 0;
    lg->ix = qev ? qev->idx : 0;
    lg->rf = (qev && qev->tsk) ? refcount_read (&qev->tsk->users) : 0;

    lg->rx = lg->tx = -1;
    lg->sz = 0;
    if (pif) {
        if (!ttp_opcode_is_ack (opc)) {
            lg->rx = pif->rxi_seq;
            lg->tx = pif->txi_seq;
            if (TTP_OP__TTP_PAYLOAD == opc) {
                lg->sz = pif->noc_len;
            }
        }
        else {
            lg->rx = pif->rxi_seq;
        }
    }

    lg->fl = strstr (fil, "modttpoe");
    lg->fn = (u8 *)fun;
    lg->ln = lin;

    if (qev && qev->kid && TTP_EVENT_IS_VALID (lg->ev)) {
        ttp_fsm_lookup_state_table (lg->kd, lg->ev, &lg->cs, &lg->ns, &lg->rs);

        if ((lt = ttp_rbtree_tag_get (lg->kd))) {
            lg->vc = lt->vci;
            lg->hv = lt->hvl;
            lg->bk = lt->bkt;
        }
    }

    list_add_tail (&lg->lm, &ttp_global_root_head.evlog_head);
    ttp_stats.evlog++;

    mutex_unlock (&ttp_global_root_head.evlog_mutx);
}


DECLARE_BITMAP (ttp_bloom_bitmap, TTP_BLOOM_SIZE);

/* using reverse-bits */
TTP_NOTRACE
static u32 ttp_bloom_hash1 (u64 kid)
{
    u64 rv = 0;

    while (kid) {
        rv   ^= kid & TTP_BLOOM_MASK;
        kid >>= TTP_BLOOM_SIZE_BITS;
        kid   = (kid & 0xffffff00) | ttp_tag_reverse_bits (kid & 0xff);
    }

    rv = (rv & TTP_BLOOM_MASK) ^ ((rv >> TTP_BLOOM_SIZE_BITS) & TTP_BLOOM_MASK);
    return rv;
}


/* using crc16 */
TTP_NOTRACE
static u32 ttp_bloom_hash2 (u64 kid)
{
    u32 rv = 0;

    while (kid) {
        rv = crc16_byte (rv, kid & 0xff);
        kid >>= 8;
    }
    rv &= 0xffff;               /* crc16 */

    rv = (rv & TTP_BLOOM_MASK) ^ ((rv >> TTP_BLOOM_SIZE_BITS) & TTP_BLOOM_MASK);
    return rv;
}


/* using a FNV-like hash function */
TTP_NOTRACE
static u32 ttp_bloom_hash3 (u64 kid)
{
    u32 rv = 0;

    while (kid) {
        rv   *= 16777619;
        rv   ^= (kid & 0xff);
        kid >>= 8;
    }

    rv = (rv & TTP_BLOOM_MASK) ^ ((rv >> TTP_BLOOM_SIZE_BITS) & TTP_BLOOM_MASK);
    return rv;
}


TTP_NOTRACE
void ttp_bloom_add (u64 kid)
{
    set_bit (ttp_bloom_hash1 (kid), ttp_bloom_bitmap);
    set_bit (ttp_bloom_hash2 (kid), ttp_bloom_bitmap);
    set_bit (ttp_bloom_hash3 (kid), ttp_bloom_bitmap);
}


TTP_NOTRACE
int ttp_bloom_test (u64 kid)
{
    return test_bit (ttp_bloom_hash1 (kid), ttp_bloom_bitmap)
        && test_bit (ttp_bloom_hash2 (kid), ttp_bloom_bitmap);
}


/* returns -1 if t1->key < t2->key, 1 if '>', and 0 when equal */
static int ttp_rbtree_tag_key_cmp (struct ttp_link_tag *t1, struct ttp_link_tag *t2)
{
    u32 k1 = t1->_rkey, k2 = t2->_rkey;

    if (k1 < k2) {
        return -1;
    }
    else if (k1 > k2) {
        return 1;
    }
    else {
        return 0;
    }
}

TTP_NOINLINE
void ttp_rbtree_tag_add (struct ttp_link_tag *tag)
{
    struct rb_node **new, *parent = NULL;
    struct ttp_link_tag *lt;
    int cmp;

    new = &ttp_global_root_head.tag_rbroot.rb_node;
    while (*new) {
        parent = *new;
        lt = rb_entry (*new, struct ttp_link_tag, rbn);

        if ((cmp = ttp_rbtree_tag_key_cmp (lt, tag)) < 0) {
            new = &((*new)->rb_left);
        }
        else if (cmp > 0) {
            new = &((*new)->rb_right);
        }
        else { /* keys are equal */
            return;
        }
    }

    rb_link_node (&tag->rbn, parent, new);
    rb_insert_color (&tag->rbn, &ttp_global_root_head.tag_rbroot);
}

TTP_NOINLINE
void ttp_rbtree_tag_del (u64 kid)
{
    struct rb_node **new, *parent = NULL;
    struct ttp_link_tag *lt, tag = {0};
    int cmp;

    tag._rkid = kid;
    new = &ttp_global_root_head.tag_rbroot.rb_node;
    while (*new) {
        parent = *new;
        lt = rb_entry (*new, struct ttp_link_tag, rbn);

        if ((cmp = ttp_rbtree_tag_key_cmp (lt, &tag)) < 0) {
            new = &((*new)->rb_left);
        }
        else if (cmp > 0) {
            new = &((*new)->rb_right);
        }
        else { /* keys are equal */
            rb_erase (&lt->rbn, &ttp_global_root_head.tag_rbroot);
        }
    }
}

TTP_NOINLINE
struct ttp_link_tag *ttp_rbtree_tag_get (u64 kid)
{
    struct rb_node **new, *parent = NULL;
    struct ttp_link_tag *lt, tag = {0};
    int cmp;

    tag._rkid = kid;
    new = &ttp_global_root_head.tag_rbroot.rb_node;
    while (*new) {
        parent = *new;
        lt = rb_entry (*new, struct ttp_link_tag, rbn);

        if ((cmp = ttp_rbtree_tag_key_cmp (lt, &tag)) < 0) {
            new = &((*new)->rb_left);
        }
        else if (cmp > 0) {
            new = &((*new)->rb_right);
        }
        else { /* found it */
            return lt;
        }
    }

    return NULL;
}


/* return 0 on failure to get pool event */
TTP_NOINLINE
static bool ttp_evt_pget_locked (struct ttp_fsm_event **evp)
{
    struct ttp_fsm_event *ev;

    if (!(ev = list_first_entry_or_null (&ttp_global_root_head.pool_head,
                                         struct ttp_fsm_event, elm))) {
        ttp_stats.ovr_fl++;
        return false;
    }
    BUG_ON (ev->rsk);
    BUG_ON (ev->tsk);

    ev->mrk = TTP_EVENTS_FENCE_FREE_ELEM;
    ev->psi.noc_len = 0;

    list_del (&ev->elm);
    ttp_stats.pool--;

    *evp = ev;
    return true;
}


/* return 0 on failure to get pool event */
bool ttp_evt_pget (struct ttp_fsm_event **evp)
{
    bool rv;

    mutex_lock (&ttp_global_root_head.event_mutx);

    rv = ttp_evt_pget_locked (evp);

    mutex_unlock (&ttp_global_root_head.event_mutx);

    return rv;
}


TTP_NOINLINE
static void ttp_evt_pput_locked (struct ttp_fsm_event *ev)
{
    if (ev->rsk) {
        if (ev->mrk == TTP_EVENTS_FENCE_RX_Q_ELEM) {
            atomic_dec (&ttp_stats.skb_ct);
        }
        ttp_skb_drop (ev->rsk);
        ev->rsk = NULL;
    }

    if (ev->tsk) {
        ttp_skb_drop (ev->tsk);
        ev->tsk = NULL;
    }

    BUG_ON (ev->rsk);
    BUG_ON (ev->tsk);

    ev->kid = 0;
    ev->evt = TTP_EV__invalid;
    ev->mrk = TTP_EVENTS_FENCE_POOL_ELEM;

    list_add_tail (&ev->elm, &ttp_global_root_head.pool_head);
    ttp_stats.pool++;
}


void ttp_evt_pput (struct ttp_fsm_event *ev)
{
    if (!ev) {
        return;
    }

    mutex_lock (&ttp_global_root_head.event_mutx);

    ttp_evt_pput_locked (ev);

    mutex_unlock (&ttp_global_root_head.event_mutx);
}

#define TTP_NUM_CHANNELS  4

TTP_NOINLINE
static int ttp_evt_getrr_locked (struct ttp_fsm_event **evp)
{
    static int rri = 0;
    int iv;
    struct list_head *qh;
    struct ttp_fsm_event *lev = NULL;
    struct list_head *qhs[TTP_NUM_CHANNELS] = { &ttp_global_root_head.rxq_head,
                                                &ttp_global_root_head.txq_head,
                                                &ttp_global_root_head.akq_head,
                                                &ttp_global_root_head.inq_head };

    for (iv = 0; iv < TTP_NUM_CHANNELS; iv++) {
        qh = qhs[rri];
        rri = (rri + 1) % TTP_NUM_CHANNELS;

        if ((lev = list_first_entry_or_null (qh, struct ttp_fsm_event, elm))) {
            *evp = lev;
            return rri;
        }
    }

    return -1;
}


TTP_UNUSED TTP_NOINLINE
static int ttp_evt_getsp_locked (struct ttp_fsm_event **evp)
{
    struct ttp_fsm_event *ev;

    if ((ev = list_first_entry_or_null (&ttp_global_root_head.rxq_head,
                                        struct ttp_fsm_event, elm))) {
        *evp = ev;
        return 0;
    }

    if ((ev = list_first_entry_or_null (&ttp_global_root_head.txq_head,
                                        struct ttp_fsm_event, elm))) {
        *evp = ev;
        return 1;
    }

    if ((ev = list_first_entry_or_null (&ttp_global_root_head.akq_head,
                                        struct ttp_fsm_event, elm))) {
        *evp = ev;
        return 2;
    }

    if ((ev = list_first_entry_or_null (&ttp_global_root_head.inq_head,
                                        struct ttp_fsm_event, elm))) {
        *evp = ev;
        return 3;
    }

    return -1;
}


TTP_NOINLINE
static int ttp_evt_dequ (void)
{
    int chnl;
    enum ttp_states_enum cs, ns;
    enum ttp_response_enum rs;
    struct ttp_fsm_event *ev;
    struct ttp_link_tag *lt;
    ttp_fsm_fn dqfnp;

    mutex_lock (&ttp_global_root_head.event_mutx);

    if ((chnl = ttp_evt_getrr_locked (&ev)) < 0) {
        mutex_unlock (&ttp_global_root_head.event_mutx);
        return 0;
    }

    list_del (&ev->elm);
    ttp_stats.queue--;

    mutex_unlock (&ttp_global_root_head.event_mutx);

    BUG_ON (ev->rsk && ev->tsk);

    /* ****************************** process event ****************************** */

    if (!TTP_EVENT_IS_VALID (ev->evt)) {
        TTP_EVLOG (ev, ev->evt, TTP_OP__invalid);
        goto end;
    }

    /* lookup fsm table */
    ttp_fsm_lookup_state_table (ev->kid, ev->evt, &cs, &ns, &rs);

    if (ttp_verbose_for_ctrl (ev->psi.noc_len)) {
        TTP_DBG ("##-> FSM Step: %s ==> %s / %s ==> %s\n",
                 TTP_STATE_NAME (cs), TTP_EVENT_NAME (ev->evt),
                 TTP_RESPONSE_NAME (rs), TTP_STATE_NAME (ns));
        TTP_DB1 ("`-> channel:%d 0x%016llx.%d rx:%d tx:%d\n", chnl,
                 cpu_to_be64 (ev->kid), ev->idx, ev->psi.rxi_seq, ev->psi.txi_seq);
    }

    TTP_EVLOG (ev, ev->evt, ttp_fsm_response_op[rs]);

    /* handle event */
    if ((lt = ttp_rbtree_tag_get (ev->kid))) {
        if (ttp_verbose_for_ctrl (ev->psi.noc_len)) {
            TTP_DB1 ("##`-> FSM Event-Handle: %s\n", TTP_EVENT_NAME (ev->evt));
            TTP_DB2 ("  `-> lt-rx:%d lt-tx:%d gw:%d tp:%d\n",
                     lt->rx_seq_id, lt->tx_seq_id, lt->gw3, lt->tp4);
        }
    }
    dqfnp = ttp_fsm_event_handle_fn[ev->evt];
    if (dqfnp && ev->rsk) {
        if (!dqfnp (ev)) {
            TTP_DB1 ("!!`-> FSM Event-Handle: %s [FAILED]\n", TTP_EVENT_NAME (ev->evt));
        }
    }

    /* do response */
    TTP_DB1 ("##`-> FSM Response: %s\n", TTP_RESPONSE_NAME (rs));
    dqfnp = ttp_fsm_response_fn[rs];
    if (dqfnp) {
        if (!dqfnp (ev)) {
            TTP_DBG ("!!`-> FSM Response: %s [FAILED]\n", TTP_RESPONSE_NAME (rs));
        }
    }

    ttp_tag_signal_tag (ev);

    /* call the state entry function for the state we're entering (ns) */
    TTP_DB1 ("##`-> FSM State-Entry: %s\n", TTP_STATE_NAME (ns));
    dqfnp = ttp_fsm_entry_function[ns];
    if (dqfnp) {
        if (!dqfnp (ev)) {
            TTP_DBG ("##`-> FSM State-Entry: %s [FAILED]\n", TTP_STATE_NAME (ns));
        }
    }
    if (lt) {
        schedule_work (&lt->wkq);
    }

    schedule_work (&ttp_global_root_head.work_queue); /* schedule work to drain queue */

    /* *************************** DONE process event *************************** */

end:
    ttp_evt_pput (ev);
    return 1;
}


TTP_NOINLINE
static void ttp_evt_enqu_locked (struct ttp_fsm_event *ev)
{
    switch (ev->evt) {
    case TTP_EV__RXQ__TTP_OPEN ... TTP_EV__RXQ__TTP_UNXP_PAYLD:
        ev->mrk = TTP_EVENTS_FENCE_RX_Q_ELEM;
        list_add_tail (&ev->elm, &ttp_global_root_head.rxq_head);
        break;

    case TTP_EV__TXQ__TTP_OPEN ... TTP_EV__TXQ__REPLAY_CLOSE:
        ev->mrk = TTP_EVENTS_FENCE_TX_Q_ELEM;
        list_add_tail (&ev->elm, &ttp_global_root_head.txq_head);
        break;

    case TTP_EV__AKQ__OPEN_ACK ... TTP_EV__AKQ__NACK:
        ev->mrk = TTP_EVENTS_FENCE_AK_Q_ELEM;
        list_add_tail (&ev->elm, &ttp_global_root_head.akq_head);
        break;

    case TTP_EV__INQ__TIMEOUT ... TTP_EV__INQ__NOT_QUIESCED:
        ev->mrk = TTP_EVENTS_FENCE_IN_Q_ELEM;
        list_add_tail (&ev->elm, &ttp_global_root_head.inq_head);
        break;

    default:
        ev->mrk = TTP_EVENTS_FENCE_EXPT_ELEM;
        list_add_tail (&ev->elm, &ttp_global_root_head.inq_head);
        break;
    }

    ttp_stats.queue++;
}


TTP_NOINLINE
static struct ttp_fsm_event *ttp_evt_cpqu_locked (const struct ttp_fsm_event *qev)
{
    struct ttp_fsm_event *ev;

    if (!ttp_evt_pget_locked (&ev)) {
        return NULL;
    }

    BUG_ON (ev->rsk);
    BUG_ON (ev->tsk);

    ev->evt = qev->evt;
    ev->kid = qev->kid;

    ttp_tsk_bind (ev, qev);

    ttp_evt_enqu_locked (ev);

    return ev;
}


int ttp_noc_dequ (struct ttp_link_tag *lt)
{
    struct ttp_fsm_event *tev;

    mutex_lock (&ttp_global_root_head.event_mutx);

    tev = list_first_entry_or_null (&lt->ncq, struct ttp_fsm_event, elm);
    if (!tev) {
        mutex_unlock (&ttp_global_root_head.event_mutx);
        return 0;
    }

    list_del (&tev->elm);

    mutex_unlock (&ttp_global_root_head.event_mutx);

    TTP_DB1 ("%s: 0x%016llx.%d evnt: %s\n", __FUNCTION__,
             cpu_to_be64 (tev->kid), tev->idx,
             TTP_EVENT_IS_VALID (tev->evt) ? TTP_EVENT_NAME (tev->evt) : "null");

    ttp_evt_pput (tev);

    return 1;
}


void ttp_noc_requ (struct ttp_link_tag *lt)
{
    static const int max_retry = 1000;
    struct ttp_fsm_event *ev, *tev;

    if (timer_pending (&lt->tmr)) {
        TTP_DBG ("%s: skip enqueue #%d\n", __FUNCTION__, lt->try);
        return;
    }

    mutex_lock (&ttp_global_root_head.event_mutx);

    tev = list_first_entry_or_null (&lt->ncq, struct ttp_fsm_event, elm);
    if (!tev) {                 /* exit if no evnt of is already in txq */
        mutex_unlock (&ttp_global_root_head.event_mutx);
        TTP_DB1 ("%s: 0x%016llx.%d\n", __FUNCTION__,
                 cpu_to_be64 (lt->_rkid), tev ? tev->idx : -1);
        return;
    }

    if (lt->try <= max_retry) { /* allow 'max_retry' re-tries */
        if (lt->txt < lt->twz) { /* cp_enqueue while under window size */
            if ((ev = ttp_evt_cpqu_locked (tev))) {
                TTP_DB1 ("%s: `-> %senqueue#%d %s len:%d tx:%d mark:%s\n", __FUNCTION__,
                         lt->try ? "re-" : "", lt->try, TTP_EVENT_NAME (tev->evt),
                         ev->psi.noc_len, ev->psi.txi_seq,
                         TTP_EVENTS_FENCE_TO_STR (tev->mrk));
                if (lt->try) {
                    TTP_EVLOG (ev, TTP_LG__NOC_PAYLOAD_REQ, TTP_OP__TTP_PAYLOAD);
                }

                TTP_RUN_SPIN_LOCKED ({
                    lt->txt++;
                    lt->try++;    /* re/try with this tx-seq-id; increment retry count */
                });

                schedule_work (&lt->wkq);
            }
        }
        mutex_unlock (&ttp_global_root_head.event_mutx);
        return;
    }

    list_del (&tev->elm);       /* HACK: exceeded retry count - retire event */

    lt->tct--;
    lt->try = 0;
    ttp_stats.nocq--;

    mutex_unlock (&ttp_global_root_head.event_mutx);

    TTP_DB1 ("%s: 0x%016llx.%d >max re-tries(%d)\n", __FUNCTION__,
             cpu_to_be64 (lt->_rkid), tev->idx, max_retry);
    TTP_EVLOG (tev, TTP_LG__NOC_PAYLOAD_DROP, TTP_OP__TTP_PAYLOAD);

    ttp_evt_pput (tev);

    /* HACK: trigger timeout to retry sending next nocq element */
    if (ttp_evt_pget (&ev)) {
        ev->evt = TTP_EV__INQ__TIMEOUT;
        ev->kid = lt->_rkid;
        ttp_evt_enqu (ev);
        TTP_DB1 ("%s: wq: evnt: int__TIMEOUT\n", __FUNCTION__);
        TTP_EVLOG (ev, TTP_LG__TIMER_TIMEOUT, TTP_OP__invalid);
    }
}


TTP_NOINLINE
static void ttp_do_global_work (struct work_struct *wk)
{
    int rv = 0;

    if (0 == ttp_stats.wkq_sz) {
        ; /* fall thro' */
    }
    else if (0 == ttp_stats.wkq_st) {
        return;
    }
    else {
        ttp_stats.wkq_st--;
    }

    rv += ttp_evt_dequ ();
    rv += ttp_skb_dequ ();
}


TTP_NOINLINE
static void ttp_do_tag_work (struct work_struct *wk)
{
    int rv = 0;
    bool do_tex = false;
    struct ttp_link_tag *lt;
    struct ttp_fsm_event *ev;

    if (0 == ttp_stats.wkq_sz) {
        ; /* fall thro' */
    }
    else if (0 == ttp_stats.wkq_st) {
        return;
    }
    else {
        ttp_stats.wkq_st--;
    }

    if (!(lt = from_work (lt, wk, wkq))) {
        return;
    }

    TTP_RUN_SPIN_LOCKED ({
        if (lt->tex) {
            lt->tex = false;
            do_tex = true;
        }
    });

    if (do_tex) {
        if (ttp_evt_pget (&ev)) {
            ev->evt = TTP_EV__INQ__TIMEOUT;
            ev->kid = lt->_rkid;
            ttp_evt_enqu (ev);
            TTP_DB1 ("%s: wq: evnt: int__TIMEOUT\n", __FUNCTION__);
            TTP_EVLOG (ev, TTP_LG__TIMER_TIMEOUT, TTP_OP__invalid);
        }
    }

    rv = ttp_evt_dequ ();
}


TTP_NOINLINE
static void ttp_fsm_tag_timer_callback (struct timer_list *tl)
{
    struct ttp_link_tag *lt;

    if (!(lt = from_timer (lt, tl, tmr))) {
        return;
    }

    /* signal that timer expired */
    lt->tex = true;

    schedule_work (&lt->wkq);
}


TTP_NOINLINE
static void ttp_fsm_global_timer_callback (struct timer_list *tl)
{
    /* placeholder for any global periodic work */
}


void ttp_evt_cpqu (struct ttp_fsm_event *ev)
{
    struct ttp_link_tag  *lt;

    mutex_lock (&ttp_global_root_head.event_mutx);

    ttp_evt_cpqu_locked (ev);

    mutex_unlock (&ttp_global_root_head.event_mutx);

    if ((lt = ttp_rbtree_tag_get (ev->kid))) {
        schedule_work (&lt->wkq);
    }
    else {
        schedule_work (&ttp_global_root_head.work_queue);
    }
}


void ttp_evt_enqu (struct ttp_fsm_event *ev)
{
    struct ttp_link_tag  *lt;

    mutex_lock (&ttp_global_root_head.event_mutx);

    ttp_evt_enqu_locked (ev);

    mutex_unlock (&ttp_global_root_head.event_mutx);

    if ((lt = ttp_rbtree_tag_get (ev->kid))) {
        schedule_work (&lt->wkq);
    }
    else {
        schedule_work (&ttp_global_root_head.work_queue);
    }

    TTP_DB1 ("%s: enqueue %s len:%d tx:%d mark:%s\n", __FUNCTION__,
             TTP_EVENT_NAME (ev->evt), ev->psi.noc_len, ev->psi.txi_seq,
             TTP_EVENTS_FENCE_TO_STR (ev->mrk));
}


void ttp_noc_enqu (struct ttp_fsm_event *ev)
{
    struct ttp_link_tag  *lt;

    if (!(lt = ttp_rbtree_tag_get (ev->kid))) {
        ttp_evt_pput (ev);
        return;
    }

    mutex_lock (&ttp_global_root_head.event_mutx);

    list_add_tail (&ev->elm, &lt->ncq);

    mutex_unlock (&ttp_global_root_head.event_mutx);

    TTP_RUN_SPIN_LOCKED ({
        ev->psi.txi_seq = lt->tx_seq_id;
        lt->tct++;
        lt->tx_seq_id++;
        ttp_stats.nocq++;
    });

    schedule_work (&lt->wkq);

    TTP_EVLOG (ev, TTP_LG__NOC_PAYLOAD_ENQ, TTP_OP__TTP_PAYLOAD);
    TTP_DB1 ("%s: enqueue %s len:%d tx:%d mark:%s\n", __FUNCTION__,
             TTP_EVENT_NAME (ev->evt), ev->psi.noc_len, ev->psi.txi_seq,
             TTP_EVENTS_FENCE_TO_STR (ev->mrk));
}


void __init ttp_fsm_init (void)
{
    int vi, hv, bk;
    struct ttp_fsm_event *ev;
    struct ttp_fsm_evlog *lg;
    struct ttp_link_tag *lt;

    mutex_init (&ttp_global_root_head.event_mutx);
    mutex_init (&ttp_global_root_head.evlog_mutx);

    /* initialize pool and queue list heads */
    skb_queue_head_init (&ttp_global_root_head.skb_head);
    INIT_LIST_HEAD (&ttp_global_root_head.pool_head);
    INIT_LIST_HEAD (&ttp_global_root_head.rxq_head);
    INIT_LIST_HEAD (&ttp_global_root_head.txq_head);
    INIT_LIST_HEAD (&ttp_global_root_head.akq_head);
    INIT_LIST_HEAD (&ttp_global_root_head.inq_head);
    INIT_LIST_HEAD (&ttp_global_root_head.evlog_head);

    /* initialize array: create pool */
    for (vi = 0; vi < TTP_EVENTS_POOL_SIZE; vi++) {
        ev = &ttp_global_root_head.event_arr[vi];

        ev->rsk = NULL;
        ev->tsk = NULL;
        ev->idx = TTP_EVENTS_INDX_OF (ev);
        ev->evt = TTP_EV__invalid;
        ev->kid = 0;
        ev->mrk = TTP_EVENTS_FENCE_POOL_ELEM;

        lg = &ttp_global_root_head.evlog_arr[vi];
        lg->ts = jiffies;

        ttp_stats.pool++;

        mutex_lock (&ttp_global_root_head.event_mutx);

        list_add_tail (&ev->elm, &ttp_global_root_head.pool_head);
        list_add_tail (&lg->lm, &ttp_global_root_head.evlog_head);

        mutex_unlock (&ttp_global_root_head.event_mutx);
    }

    /* setup timers */
    timer_setup (&ttp_global_root_head.timer_head, &ttp_fsm_global_timer_callback, 0);
    INIT_WORK   (&ttp_global_root_head.work_queue, ttp_do_global_work);
    ttp_global_root_head.tag_rbroot = RB_ROOT;

    spin_lock_init (&ttp_global_root_head.spin_lock);

    for (hv = 0; hv < TTP_TAG_TBL_SIZE; hv++) {
        for (bk = 0; bk < TTP_TAG_TBL_BKTS_NUM; bk++) {
            lt = &ttp_link_tag_tbl_0[hv][bk];
            timer_setup (&lt->tmr, &ttp_fsm_tag_timer_callback, 0);
            INIT_WORK (&lt->wkq, ttp_do_tag_work);
            INIT_LIST_HEAD (&lt->ncq);
            ttp_tag_reset (lt);

            lt = &ttp_link_tag_tbl_1[hv][bk];
            timer_setup (&lt->tmr, &ttp_fsm_tag_timer_callback, 0);
            INIT_WORK (&lt->wkq, ttp_do_tag_work);
            INIT_LIST_HEAD (&lt->ncq);
            ttp_tag_reset (lt);

            lt = &ttp_link_tag_tbl_2[hv][bk];
            timer_setup (&lt->tmr, &ttp_fsm_tag_timer_callback, 0);
            INIT_WORK (&lt->wkq, ttp_do_tag_work);
            INIT_LIST_HEAD (&lt->ncq);
            ttp_tag_reset (lt);
        }
    }
}

void __exit ttp_fsm_exit (void)
{
    int vi, hv, bk;
    struct ttp_fsm_event *ev;

    mutex_lock (&ttp_global_root_head.event_mutx);

    /* free all allocated buffers */
    for (vi = 0; vi < TTP_EVENTS_POOL_SIZE; vi++) {
        ev = &ttp_global_root_head.event_arr[vi];
        kfree_skb (ev->rsk);
        ev->rsk = NULL;
        kfree_skb (ev->tsk);
        ev->tsk = NULL;
        ttp_evt_pput_locked (ev);
    }

    /* delete all pool timers */
    for (hv = 0; hv < TTP_TAG_TBL_SIZE; hv++) {
        for (bk = 0; bk < TTP_TAG_TBL_BKTS_NUM; bk++) {
            del_timer (&ttp_link_tag_tbl_0[hv][bk].tmr);
            del_timer (&ttp_link_tag_tbl_1[hv][bk].tmr);
            del_timer (&ttp_link_tag_tbl_2[hv][bk].tmr);
        }
    }
    del_timer (&ttp_global_root_head.timer_head);

    mutex_unlock (&ttp_global_root_head.event_mutx);
}
