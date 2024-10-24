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

/*             Ttpoe  OPCODES
 * +=======+======+======+======+======+
 * |       | OPEN | CLOSE| DATA | LINK |
 * +=======+======+======+======+======+
 * | ident |   0  |   3  |   6  |  --  |
 * +-------+------+------+------+------+
 * |   ACK |   1  |   4  |   7  |   9  |
 * +-------+------+------+------+------+
 * |  NACK |   2  |   5  |   8  |  10  |
 * +=======+======+======+======+======+
 */
/* Opcode values must be kept to be combatible with HW */
enum ttp_opcodes_enum {
    TTP_OP__TTP_OPEN            =  0,
    TTP_OP__TTP_OPEN_ACK        =  1,
    TTP_OP__TTP_OPEN_NACK       =  2,

    TTP_OP__TTP_CLOSE           =  3,
    TTP_OP__TTP_CLOSE_ACK       =  4,
    TTP_OP__TTP_CLOSE_NACK      =  5,

    TTP_OP__TTP_PAYLOAD         =  6,
    TTP_OP__TTP_ACK             =  7,
    TTP_OP__TTP_NACK            =  8,

    TTP_OP__TTP_NACK_FULL       =  9,
    TTP_OP__TTP_NACK_NOLINK     = 10,

    TTP_OP__invalid             = 11,
    TTP_OP__NUM_OP              = TTP_OP__invalid,
    TTP_OP__TTP_LINK,           /* Future -- */
};
extern char *ttp_opcode_names[];

static inline bool ttp_opcode_is_ack (enum ttp_opcodes_enum op)
{
    switch (op) {
    case TTP_OP__TTP_OPEN_ACK:
    case TTP_OP__TTP_OPEN_NACK:
    case TTP_OP__TTP_CLOSE_ACK:
    case TTP_OP__TTP_CLOSE_NACK:
    case TTP_OP__TTP_ACK:
    case TTP_OP__TTP_NACK:
    case TTP_OP__TTP_NACK_FULL:
    case TTP_OP__TTP_NACK_NOLINK:
        return true;
    default:
        return false;
    }
}


/*         TTPoE  FSM  STATES
 * +=======+============+===========+
 * |       | CLOSED *** | OPEN ***  |
 * +=======+============+===========+
 * | ident | CLOSED     | OPEN      |  
 * +-------+------------+-----------+
 * |  SENT | CLOSE_SENT | OPEN_SENT |
 * +-------+------------+-----------+
 * |  RECD | CLOSE_RECD | OPEN_RECD |
 * +=======+============+===========+
 */
enum ttp_states_enum {
    TTP_ST__stay = 0,           /* must be zero */
    TTP_ST__CLOSED,
    TTP_ST__OPEN_SENT,
    TTP_ST__OPEN_RECD,
    TTP_ST__OPEN,
    TTP_ST__CLOSE_SENT,
    TTP_ST__CLOSE_RECD,

    TTP_ST__invalid,
    TTP_ST__NUM_ST = TTP_ST__invalid,
};
extern char *ttp_state_names[];


/* enumeration of all events to the TTP FSM, organized by channel & source */
enum ttp_events_enum {
    TTP_EV__null = 0,

    /* host originated events (TX queue, NOC is host): --> txq_head*/
    TTP_EV__TXQ__TTP_OPEN,
    TTP_EV__TXQ__TTP_CLOSE,
    TTP_EV__TXQ__TTP_PAYLOAD,

    TTP_EV__TXQ__REPLAY_DATA,
    TTP_EV__TXQ__REPLAY_CLOSE,


    /* Network originated events (RX queue): --> rxq_head */
    TTP_EV__RXQ__TTP_OPEN,         /* maps to TTP_OP__TTP_OPEN */
    TTP_EV__RXQ__TTP_OPEN_ACK,     /* maps to TTP_OP__TTP_OPEN_ACK */
    TTP_EV__RXQ__TTP_OPEN_NACK,    /* maps to TTP_OP__TTP_OPEN_NACK */
    TTP_EV__RXQ__TTP_CLOSE,        /* maps to TTP_OP__TTP_CLOSE */
    TTP_EV__RXQ__TTP_CLOSE_ACK,    /* maps to TTP_OP__TTP_CLOSE_ACK */
    TTP_EV__RXQ__TTP_CLOSE_NACK,   /* maps to TTP_OP__TTP_CLOSE_NACK */
    TTP_EV__RXQ__TTP_PAYLOAD,      /* maps to TTP_OP__TTP_PAYLOAD */
    TTP_EV__RXQ__TTP_ACK,          /* maps to TTP_OP__TTP_ACK */
    TTP_EV__RXQ__TTP_NACK,         /* maps to TTP_OP__TTP_NACK */
    TTP_EV__RXQ__TTP_NACK_FULL,    /* maps to TTP_OP__TTP_NACK_FULL */
    TTP_EV__RXQ__TTP_NACK_NOLINK,  /* maps to TTP_OP__TTP_NACK_NOLINK */

    /* extra event to signal unexpected payload, w/o interfering with opcodes sequence */
    TTP_EV__RXQ__TTP_UNXP_PAYLD,


    /* internal events: outputs (ACK queue): --> akq_head */
    TTP_EV__AKQ__OPEN_ACK,
    TTP_EV__AKQ__OPEN_NACK,
    TTP_EV__AKQ__CLOSE_ACK,
    TTP_EV__AKQ__CLOSE_NACK,
    TTP_EV__AKQ__ACK,
    TTP_EV__AKQ__NACK,


    /* internal events: inputs (INT queue): --> inq_head */
    TTP_EV__INQ__TIMEOUT,
    TTP_EV__INQ__VICTIM,
    TTP_EV__INQ__FOUND_WAY,
    TTP_EV__INQ__NO_WAY,
    TTP_EV__INQ__ALLOC_TAG,
    TTP_EV__INQ__NO_TAG,
    TTP_EV__INQ__YES_QUIESCED,
    TTP_EV__INQ__NOT_QUIESCED,


    /* invalid / max */
    TTP_EV__invalid,
    TTP_EV__NUM_EV = TTP_EV__invalid,


    /* Enum values below this line are *FAKE* events relative to the TTPoE State-Machine.
     * These are used only to add entries to the 'evlog' to help trace debugging */
    TTP_LG__TTP_INIT,

    TTP_LG__TTP_LINK_UP,
    TTP_LG__TTP_LINK_DOWN,

    TTP_LG__PKT_RX,
    TTP_LG__PKT_TX,
    TTP_LG__PKT_DROP,

    TTP_LG__NOC_LINK_OPEN,
    TTP_LG__NOC_LINK_CLOSE,

    TTP_LG__NOC_PAYLOAD_TX,
    TTP_LG__NOC_PAYLOAD_RX,
    TTP_LG__NOC_PAYLOAD_ENQ,
    TTP_LG__NOC_PAYLOAD_REQ,
    TTP_LG__NOC_PAYLOAD_DUP,
    TTP_LG__NOC_PAYLOAD_DROP,
    TTP_LG__NOC_PAYLOAD_FREE,

    TTP_LG__SH_TIMER_START,
    TTP_LG__SH_TIMER_RESTART,
    TTP_LG__LN_TIMER_START,
    TTP_LG__LN_TIMER_RESTART,
    TTP_LG__TIMER_TIMEOUT,
    TTP_LG__TIMER_DELETE,

    TTP_LG__invalid,
};

enum ttp_response_enum {
    TTP_RS__none = 0,

    TTP_RS__OPEN,
    TTP_RS__OPEN_ACK,
    TTP_RS__OPEN_NACK,

    TTP_RS__CLOSE,
    TTP_RS__CLOSE_ACK,
    TTP_RS__CLOSE_XACK,

    TTP_RS__REPLAY_DATA,
    TTP_RS__PAYLOAD,
    TTP_RS__PAYLOAD2,
    TTP_RS__ACK,
    TTP_RS__NACK,

    TTP_RS__NACK_NOLINK,

    TTP_RS__NOC_FAIL,
    TTP_RS__NOC_END,

    TTP_RS__ILLEGAL,
    TTP_RS__INTERRUPT,
    TTP_RS__DROP,

    TTP_RS__STALL,

    TTP_RS__invalid,
    TTP_RS__NUM_EV = TTP_RS__invalid,
};

/* forward declarations */
struct ttp_fsm_evlog;
struct ttp_fsm_event;

struct ttp_fsm_state_var {
    enum ttp_response_enum response;
    enum ttp_states_enum   next_state;
};

typedef bool (*ttp_fsm_fn)(struct ttp_fsm_event *qev);
extern ttp_fsm_fn ttp_fsm_event_handle_fn[];
extern ttp_fsm_fn ttp_fsm_response_fn[];
extern enum ttp_opcodes_enum ttp_fsm_response_op[];
extern enum ttp_events_enum ttp_opcodes_to_events_map[];

#define TTP_OPCODE_TO_EVENT(opc)   (ttp_opcodes_to_events_map[(opc)])
#define TTP_OPCODE_IS_VALID(opc)   (((opc)>=TTP_OP__TTP_OPEN) && ((opc)<TTP_OP__invalid))

extern void ttp_fsm_state_function (struct ttp_fsm_event *ev);
