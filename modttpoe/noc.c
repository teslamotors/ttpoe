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

#include <linux/ctype.h>
#include <linux/version.h>
#include <linux/cdev.h>
#include <linux/skbuff.h>
#include <linux/etherdevice.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/inet.h>
#include <linux/types.h>
#include <linux/bitops.h>
#include <linux/cred.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/proc_fs.h>
#include <net/addrconf.h>
#include <net/ip.h>

#include <ttp.h>

#include "ttpoe.h"
#include "fsm.h"
#include "tags.h"
#include "print.h"
#include "noc.h"


/* debug noc page */
static int ttp_noc_debug_len;
static u8 *ttp_noc_debug_page;

#define TTP_MAJOR_DEV_NUM           446

static struct class *ttp_class;
static struct device *ttp_device;

#define TTP_TARGET_INVALID  (-1)
struct ttpoe_host_info ttp_debug_source;
struct ttpoe_host_info ttp_debug_target;


int ttpoe_noc_debug_tgt (u64 *kid, struct ttpoe_host_info *tg)
{
    u64 tkid;
    u32 node, mask;
    u8  mac[ETH_ALEN];

    if (!kid) {
        return -EINVAL;
    }
    if (!tg->ve) {
        return -EHOSTDOWN;
    }
    if (!ttp_ipv4_encap) {
        if (!is_valid_ether_addr (tg->mac)) {
            return -EDESTADDRREQ;
        }
        ttp_prepare_mac_with_oui (mac, TESLA_MAC_OUI, &tg->mac[3]);
        if (tg->gw && memcmp (tg->mac, mac, ETH_ALEN/2)) {
            /* don't create tag for target and return; it could be a gw-ctrl pkt */
            return 0;
        }
        tkid = ttp_tag_key_make (mac, tg->vc, tg->gw, ttp_ipv4_encap);
    }
    else {
        if (!tg->ipa || !ttp_ipv4_pfxlen) {
            return -EDESTADDRREQ;
        }
        mask = inet_make_mask (ttp_ipv4_pfxlen);
        node = tg->ipa & ~mask; /* get host part */
        ttp_prepare_mac_with_oui (mac, TESLA_MAC_OUI, (u8 *)&node + 1);
        tkid = ttp_tag_key_make (mac, tg->vc, false, ttp_ipv4_encap);
    }
    if (tkid == ttp_debug_source.kid) {
        return -EADDRINUSE;
    }

    *kid = tkid;
    ttp_tag_add (tkid);

    if (ttp_ipv4_encap) {
        TTP_DB2 ("0x%016llx: ttp-target.ip:%pI4 vc:%d gw:%d\n", cpu_to_be64 (tkid),
                 &tg->ipa, tg->vc, tg->gw);
    }
    else {
        TTP_DB2 ("0x%016llx: ttp-target.mac:%*phC vc:%d gw:%d\n", cpu_to_be64 (tkid),
                 ETH_ALEN, mac, tg->vc, tg->gw);
    }
    return 0;
}


int ttpoe_noc_debug_rx (const u8 *data, u16 nl)
{
    BUG_ON (!nl);

    if (!ttp_noc_debug_page) {
        TTP_LOG ("*** No NOC page (UNEXPECTED !! Did proc_init fail?) ***\n");
        atomic_inc (&ttp_stats.drp_ct);
        return -1;
    }

    /* Is this where we would need to handle host-side congestion ? */
    if ((TTP_NOC_DEBUG_PAGE_SIZE - ttp_noc_debug_len) < nl) {
        TTP_DBG ("******** Dropped payload: No space in NOC page ********\n");
        atomic_inc (&ttp_stats.drp_ct);
        return -1;
    }

    memcpy (ttp_noc_debug_page + ttp_noc_debug_len, data, nl);
    ttp_noc_debug_len += nl;

    TTP_DB1 ("%s: ^^^^ Put payload:%u -> debug-noc page\n", __FUNCTION__, nl);
    return 0;
}


int ttpoe_noc_debug_tx (u8 *buf, struct sk_buff *skb, int nl,
                        enum ttp_events_enum evnt, struct ttpoe_host_info *tg)
{
    int rv;
    u64 kid = 0;
    struct ttp_fsm_event *ev;
    struct ttp_link_tag clt = {0}, *lt = NULL;

    if (skb && !nl) {
        kfree_skb (skb);
        return -EINVAL;
    }
    if (nl == 2) { /* control pkt */
        TTP_DB2 ("%s: Control pkt target.vc: %*phC.%d gw:%d valid:%d len:%d\n",
                 __FUNCTION__, ETH_ALEN, tg->mac, tg->vc, tg->gw, tg->ve, nl);
        clt._rkid = kid;
        clt.gwf = 1;
        kid = clt._rkid;
        goto force;
    }
    if ((rv = ttpoe_noc_debug_tgt (&kid, tg))) {
        TTP_DBG ("%s: Error: Invalid target.vc: %*phC.%d gw:%d valid:%d\n",
                 __FUNCTION__, ETH_ALEN, tg->mac, tg->vc, tg->gw, tg->ve);
        return rv;
    }

    if (!(lt = ttp_rbtree_tag_get (kid))) {
        if (skb) {
            return -ENOKEY;       /* for a valid tx-skb, we need an existing tag */
        }

        /* noc-control: tag not found, try to allocate */
        ttp_bloom_add (kid);
        if ((rv = ttp_tag_add (kid)) < 0) {
            return -ENOKEY;     /* error: no tag key */
        }
        if (1 == rv) {
            return -ENFILE;     /* all buckets full, no way */
        }

        /* tag allocate success: get 'lt' again */
        if (!(lt = ttp_rbtree_tag_get (kid))) {
            return -ENOKEY;     /* for non-zero len, we need a valid tag */
        }
    }

force:
    if (!ttp_evt_pget (&ev)) {
        return -ENOBUFS;
    }

    ev->evt = evnt;
    ev->kid = kid;

    if (ttp_verbose_for_ctrl (nl)) {
        TTP_DBG ("%s: 0x%016llx.%d evnt:%s nl:%d\n", __FUNCTION__,
                 cpu_to_be64 (kid), ev->idx, TTP_EVENT_NAME (evnt), nl);
    }

    if (TTP_EV__TXQ__TTP_PAYLOAD != evnt) {
        ev->mrk = TTP_EVENTS_FENCE__CTL_ELEM;
        BUG_ON (skb);
        ttp_evt_enqu (ev);
        return 0;
    }

    BUG_ON (!skb);

    ev->mrk = TTP_EVENTS_FENCE__NOC_ELEM;
    ev->psi.noc_len = nl;
    ev->tsk = skb;
    ev->psi.skb_dat = buf;
    ev->psi.skb_len = skb->len;

    TTP_EVLOG (ev, TTP_LG__NOC_PAYLOAD_TX, TTP_OP__TTP_PAYLOAD);

    ttp_noc_enqu (ev);
    if (lt) {
        ttp_noc_requ (lt);
    }

    TTP_DB1 ("%s: vvvv Got payload:%u <- debug-noc page\n", __FUNCTION__, nl);
    return nl;
}


/*
 * cat /dev/null > noc_debug : Clear noc-debug-rx-page (does not reset ttp link)
 *   echo STRING > noc_debug : Send STRG as payload to peer (open ttp link if needed)
 *             cat noc_debug : Read out noc-debug-rx-page
 *       diff FILE noc_debug : Compare noc-debug-rx-page with FILE
 */
static ssize_t ttpoe_noc_debug_write (struct file *filp, const char __user *user_buf,
                                      size_t nbytes, loff_t *ppos)
{
    u8 *buf;
    int rv;
    struct sk_buff *skb;
    struct ttp_frame_hdr frh;

    if (nbytes < 1) {
        return -EFAULT;
    }

    if (ttp_shutdown) {
        TTP_DBG ("%s: noc debug payload dropped: ttp is shutdown\n", __FUNCTION__);
        return -ENETDOWN;
    }

    filp->private_data = &ttp_debug_target;

    if (nbytes > TTP_NOC_DAT_SIZE) {
        nbytes = TTP_NOC_DAT_SIZE;
    }

    if (!ttp_debug_target.ve) {
        return -EHOSTDOWN;
    }

    if (!ttp_ipv4_encap) {
        if (!is_valid_ether_addr (ttp_debug_target.mac)) {
            TTP_DBG ("%s: Error: Invalid target.vc: %*phC.%d\n", __FUNCTION__,
                     ETH_ALEN, ttp_debug_target.mac, ttp_debug_target.vc);
            return -EADDRNOTAVAIL;
        }
    }
    else {
        if (!ttp_debug_target.ipa) {
            TTP_DBG ("%s: Error: Invalid target.vc: %pi$.%d\n", __FUNCTION__,
                     &ttp_debug_target.ipa, ttp_debug_target.vc);
            return -EADDRNOTAVAIL;
        }
    }

    if (!(buf = ttp_skb_aloc (&skb, nbytes))) {
        return -ENOMEM;
    }

    ttp_skb_pars (skb, &frh, NULL);
    if ((rv = copy_from_user (frh.noc, user_buf, nbytes))) {
        ttp_skb_drop (skb);
        goto end;
    }

    if ((rv = ttpoe_noc_debug_tx (buf, skb, nbytes, TTP_EV__TXQ__TTP_PAYLOAD,
                                  &ttp_debug_target)) < 0) {
        ttp_skb_drop (skb);
        goto end;
    }

    return nbytes;

end:
    return rv;
}

static int ttpoe_noc_debug_open (struct inode *inode, struct file *filp)
{
    return 0;
}

static int ttpoe_noc_debug_mmap (struct file *filp, struct vm_area_struct *vma)
{
    vma->vm_pgoff = virt_to_phys (ttp_noc_debug_page) >> PAGE_SHIFT;
    return remap_pfn_range (vma, vma->vm_start, vma->vm_pgoff,
                            vma->vm_end - vma->vm_start, vma->vm_page_prot);
}

static ssize_t ttpoe_noc_debug_read (struct file *filp, char *buf,
                                     size_t nbytes, loff_t *ppos)
{
    int kc, rc;

    TTP_DB1 ("%s: %s (%lld/%zu)\n", __FUNCTION__, filp->f_path.dentry->d_name.name,
             *ppos, nbytes);

    if (*ppos < 0) {
        return -EIO;
    }

    filp->private_data = &ttp_debug_target;

    kc = min ((int)(ttp_noc_debug_len - *ppos), (int)nbytes);
    if (*ppos >= ttp_noc_debug_len) {
        return 0;
    }

    if ((rc = copy_to_user (buf, ttp_noc_debug_page + *ppos, kc)) < 0) {
        return -EIO;
    }

    *ppos += kc;
    return kc;
}

static int ttpoe_noc_debug_release (struct inode *inode, struct file *filp)
{
    /* filp->private_data didn't get set by read/write => Erase noc-buffer */
    if (!filp->private_data) {
        ttp_noc_debug_len = 0;
        memset (ttp_noc_debug_page, 0, PAGE_SIZE);
        TTP_DB1 ("%s: noc_debug: Erased\n", __FUNCTION__);
    }

    return 0;
}


static const struct file_operations ttpoe_noc_debug_fops = {
    .owner = THIS_MODULE,
    .open = ttpoe_noc_debug_open,
    .mmap = ttpoe_noc_debug_mmap,
    .read = ttpoe_noc_debug_read,
    .write = ttpoe_noc_debug_write,
    .release = ttpoe_noc_debug_release,
};


int __init ttpoe_noc_debug_init (void)
{
    int rv;

    if (!(ttp_noc_debug_page = (char *)get_zeroed_page (GFP_DMA))) {
        rv = -ENOMEM;
        goto out;
    }

    if ((rv = register_chrdev (TTP_MAJOR_DEV_NUM, "ttpoe",
                               &ttpoe_noc_debug_fops)) < 0) {
        rv = -EIO;
        goto out;
    }

    if (IS_ERR (ttp_class = ttp_wrap_class_create ("ttpoe"))) {
        rv = PTR_ERR (ttp_class);
        goto out;
    }

    ttp_class->dev_uevent = ttp_dev_uevent;
    if (IS_ERR (ttp_device = device_create (ttp_class, NULL,
                                            MKDEV (TTP_MAJOR_DEV_NUM, 0),
                                            NULL, "noc_debug"))) {
        rv = PTR_ERR (ttp_device);
        goto out;
    }

    return 0;

out:
    if (ttp_device) {
        device_destroy (ttp_class, MKDEV (TTP_MAJOR_DEV_NUM, 0));
    }
    if (ttp_class) {
        class_destroy (ttp_class);
    }
    if (ttp_noc_debug_page) {
        free_page ((unsigned long)ttp_noc_debug_page);
    }

    TTP_LOG ("noc_debug %s create failed!\n", rv ? "char" : "proc");
    return rv;
}


void __exit ttpoe_noc_debug_exit (void)
{
    device_destroy (ttp_class, MKDEV (TTP_MAJOR_DEV_NUM, 0));
    class_destroy (ttp_class);
    unregister_chrdev (TTP_MAJOR_DEV_NUM, "noc_debug");
    if (ttp_noc_debug_page) {
        free_page ((unsigned long)ttp_noc_debug_page);
    }
}
