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

#define TTPOE_PRBUF_MAX       1024
#define TTP_RAW(bb,ll)  ttpoe_pretty_print_data (" raw: ", 16, (bb), (ll))
#define TTP_RWS(bb,ll)  ttpoe_pretty_print_data (" raw: ", 16, (bb), ((ll)>16 ? 16:(ll)))

extern char *ttp_opcode_names[];
#define TTP_OPCODE_NAME(nm)                                 \
    ({                                                      \
        enum ttp_opcodes_enum _nm = (nm);                   \
        _nm = _nm < TTP_OP__TTP_OPEN ? TTP_OP__invalid :    \
            _nm >= TTP_OP__invalid ? TTP_OP__invalid : _nm; \
        ttp_opcode_names[_nm];                              \
    })

extern char *ttp_state_names[];
#define TTP_STATE_NAME(nm)                                  \
    ({                                                      \
        enum ttp_states_enum _nm = (nm);                    \
        _nm = _nm < TTP_ST__stay ? TTP_ST__invalid :        \
            _nm >= TTP_ST__invalid ? TTP_ST__invalid : _nm; \
        ttp_state_names[_nm];                               \
    })

extern char *ttp_sef_names[];
#define TTP_SEF_NAME(nm)                                    \
    ({                                                      \
        enum ttp_states_enum _nm = (nm);                    \
        _nm = _nm < TTP_ST__stay ? TTP_ST__invalid :        \
            _nm >= TTP_ST__invalid ? TTP_ST__invalid : _nm; \
        ttp_sef_names[_nm];                                 \
    })

extern char *ttp_state_names_short[];
#define TTP_STATE_NAME_SH(nm)                               \
    ({                                                      \
        enum ttp_states_enum _nm = (nm);                    \
        _nm = _nm < TTP_ST__stay ? TTP_ST__invalid :        \
            _nm >= TTP_ST__invalid ? TTP_ST__invalid : _nm; \
        ttp_state_names_short[_nm];                         \
    })

#define TTP_EVENT_IS_VALID(nm)                              \
    (!(nm < TTP_EV__null || nm >= TTP_EV__invalid))

extern char *ttp_event_names[];
#define TTP_EVENT_NAME(nm)                                  \
    ({                                                      \
        enum ttp_events_enum _nm = (nm);                    \
        _nm = _nm < TTP_EV__null ? TTP_EV__invalid :        \
            _nm >= TTP_EV__invalid ? TTP_EV__invalid : _nm; \
        ttp_event_names[_nm];                               \
    })

extern char *ttp_response_names[];
#define TTP_RESPONSE_NAME(nm)                               \
    ({                                                      \
        enum ttp_response_enum _nm = (nm);                  \
        _nm = _nm < TTP_RS__none ? TTP_RS__invalid :        \
            _nm >= TTP_RS__invalid ? TTP_RS__invalid : _nm; \
        ttp_response_names[_nm];                            \
    })

extern char *ttp_evlog_names[];
#define TTP_EVLOG_NAME(nm)                                  \
    ({                                                      \
        enum ttp_events_enum _nm = (nm);                    \
        _nm = _nm < TTP_LG__TTP_INIT ? TTP_LG__invalid :    \
            _nm >= TTP_LG__invalid ? TTP_LG__invalid : _nm; \
        ttp_evlog_names[_nm];                               \
    })

extern char *ttp_evlog_glyph[];
#define TTP_EVLOG_GLYPH(nm)                                 \
    ({                                                      \
        enum ttp_events_enum _nm = (nm);                    \
        _nm = _nm < TTP_LG__TTP_INIT ? TTP_LG__invalid :    \
            _nm >= TTP_LG__invalid ? TTP_LG__invalid : _nm; \
        ttp_evlog_glyph[_nm];                               \
    })

extern char *ttp_evlog_dir[];
#define TTP_EVLOG_DIR(nm)                                   \
    ({                                                      \
        enum ttp_events_enum _nm = (nm);                    \
        _nm = _nm < TTP_LG__TTP_INIT ? TTP_LG__invalid :    \
            _nm >= TTP_LG__invalid ? TTP_LG__invalid : _nm; \
        ttp_evlog_dir[_nm];                                 \
    })

extern void ttpoe_pretty_print_data (const u8 *caption, const int bpl,
                                     const u8 *buf, const int buflen);
extern void ttpoe_parse_print (const struct sk_buff *, enum ttp_frame_direction dir, int);

static inline bool ttp_verbose_for_ctrl (int nl)
{
    /* higher verbose lvl for control pkt */
    return ((ttp_verbose && nl != 2) || (ttp_verbose > 2 && nl == 2));
}

static inline void ttp_print_evt_hdr (struct seq_file *seq)
{
    seq_printf (seq, "Tag V B VC  ------- event -------   len   rx-seq"
                "   tx-seq   ret-id  ------- kid --------  mark\n");
}
static inline void ttp_print_tag_hdr (struct seq_file *seq)
{
    seq_printf (seq, "Tag V B VC  ST  Q X Y    mac-addr gw   rx-seq"
                "   tx-seq   ret-id   #op/nl   ------ kid -------\n");
}


extern void ttp_print_tag_val (struct seq_file *seq, const struct ttp_link_tag *lt);
extern void ttp_print_evt_val (struct seq_file *seq, const struct ttp_fsm_event *ev);
