<!--# SPDX-License-Identifier: GPL-2.0-or-later, Open Source License Attribution 4.0 \
International via https://creativecommons.org/licenses/by/4.0/
# 2024 Tesla Inc. 
#
# TTPoE -- Tesla Transport Protocol over Ethernet -- Open Source Publication
#
#
# TTP-Spec:   Eric Quinnell <equinnell@tesla.com>
#             Doug Williams
#             Christopher Hsiong
#             Gerardo Navarro Hurtado
#             William Lemaire
#             Diwakar Tundlam
#             Mackenzie Goodwin
#
# TTP kernel  A reference implementation of Tesla Transfer Protocol (TTP) that runs
#             directly over Ethernet Layer-2 Network. This is implemented as a Loadable
#             Kernel Module that establishes a TTP-peer connection with another instance
#             of the same module running on another Linux machine on the same Layer-2
#             network. Since TTP runs over Ethernet, it is often referred to as TTP Over
#             Ethernet (TTPoE).
#
#             The Protocol is specified to work at high bandwidths over 100Gbps and is
#             mainly designed to be implemented in Hardware as part of Tesla's DOJO
#             project.
#
#             This public release of the TTP software implementation is aligned with the
#             patent disclosure and public release of the main TTP Protocol
#             specification. Users of this software module must take into consideration
#             those disclosures in addition to the license agreement mentioned here.
#
# Authors:    Diwakar Tundlam <dntundlam@tesla.com>
#             Bill Chang <wichang@tesla.com>
#             Spencer Sharkey <spsharkey@tesla.com>
#
# Version:    08/26/2022 wichang@tesla.com, "Initial version"
#             02/09/2023 spsharkey@tesla.com, "add ttpoe header parser + test"
#             05/11/2023 dntundlam@tesla.com, "ttpoe layers - nwk, transport, payload"
#             07/11/2023 dntundlam@tesla.com, "functional state-machine, added tests"
#             08/29/2023 dntundlam@tesla.com, "final touches"
#
# This software is licensed under the terms of the GNU General Public License version 2
# as published by the Free Software Foundation, and may be copied, distributed, and
# modified under those terms.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; Without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE. See the GNU General Public License for more details.
#-->

````{verbatim}
 /$$$$$$$$                  /$$                                                       
|__  $$__/                 | $$                                                       
   | $$  /$$$$$$   /$$$$$$$| $$  /$$$$$$                                              
   | $$ /$$__  $$ /$$_____/| $$ |____  $$                                             
   | $$| $$$$$$$$|  $$$$$$ | $$  /$$$$$$$                                             
   | $$| $$_____/ \____  $$| $$ /$$__  $$                                             
   | $$|  $$$$$$$ /$$$$$$$/| $$|  $$$$$$$                                             
   |__/ \_______/|_______/ |__/ \_______/                                             
                                                                                      
                                                                                    
 /$$$$$$$$                                                                     /$$    
|__  $$__/                                                                    | $$    
   | $$  /$$$$$$  /$$$$$$  /$$$$$$$   /$$$$$$$  /$$$$$$   /$$$$$$   /$$$$$$  /$$$$$$  
   | $$ /$$__  $$|____  $$| $$__  $$ /$$_____/ /$$__  $$ /$$__  $$ /$$__  $$|_  $$_/  
   | $$| $$  \__/ /$$$$$$$| $$  \ $$|  $$$$$$ | $$  \ $$| $$  \ $$| $$  \__/  | $$    
   | $$| $$      /$$__  $$| $$  | $$ \____  $$| $$  | $$| $$  | $$| $$        | $$ /$$
   | $$| $$     |  $$$$$$$| $$  | $$ /$$$$$$$/| $$$$$$$/|  $$$$$$/| $$        |  $$$$/
   |__/|__/      \_______/|__/  |__/|_______/ | $$____/  \______/ |__/         \___/  
                                              | $$                                    
                                              | $$                                    
                                              |__/                                    
 /$$$$$$$                       /$$                                   /$$             
| $$__  $$                     | $$                                  | $$             
| $$  \ $$ /$$$$$$   /$$$$$$  /$$$$$$    /$$$$$$   /$$$$$$$  /$$$$$$ | $$             
| $$$$$$$//$$__  $$ /$$__  $$|_  $$_/   /$$__  $$ /$$_____/ /$$__  $$| $$             
| $$____/| $$  \__/| $$  \ $$  | $$    | $$  \ $$| $$      | $$  \ $$| $$             
| $$     | $$      | $$  | $$  | $$ /$$| $$  | $$| $$      | $$  | $$| $$             
| $$     | $$      |  $$$$$$/  |  $$$$/|  $$$$$$/|  $$$$$$$|  $$$$$$/| $$             
|__/     |__/       \______/    \___/   \______/  \_______/ \______/ |__/             
                                                                                      
                                                                                
````

# Introduction

At HotChips 2024, Tesla announced the open-sourcing of the Tesla Transport Protocol over Ethernet (TTPoE), represented on this GitHub repo.

Tesla also announced joining the Ultra Ethernet Consortium (UEC) to share this protocol and work to standardize a new high-speed/low-latency fabric (be that TTPoE or otherwise) for AI/ML/Datacenters -- desiring a non-proprietary, low cost, distributed congestion control, standard EthernetII frame, and non-centralized interconnect protocol to commoditize and accelerate technical progress.

In TTPoE, just like TCP, dropped packets and replays are the acceptable default behavior, yet full transmission is guaranteed.

TTPoE's initial deployment was for the Tesla Dojo v1 project, where the protocol executed entirely in hardware and deployed to a very large multi-ExaFlops (fp16) supercomputer with over 10s of thousands of concurrent endpoints. This protocol does not need a CPU or OS to be involved in any way to link and execute.

If you came here to be impressed by something complex and clever, you won't be. The protocol is designed on basic fundamentals -- simple transport and to the point. Ethernet transport in essence is only intended to move data from point A to B and should be limited by physics -- not software execution time. Centralized congestion management of extremely large scale machines (just like the internet) is a fool's errand -- each endpoint should be resiliant and self-managing. 

Eric Quinnell -- Sept 13, 2024

# TTPoE Transport Header

````{verbatim}
/* Transport Header (TTP) that follows TSH
*
*  15  14  13  12  11  10   9   8   7   6   5   4   3   2   1   0
* +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
* |         opcode [7:0]          |             vc [7:0]          |
* +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
* |             tx [7:0]          |             rx [7:0]          |
* +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
* |                          epoch [15:0]                         |
* +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
* |         congestion [7:0]      |      reserved-byte [7:0]      |
* +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
* |      reserved-byte [7:0]      |          extension [7:0]      |
* +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
* |                       tx-sequence [31:0]                      |
* |                                                               |
* +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
* |                       rx-sequence [31:0]                      |
* |                                                               |
* +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
*/
````

# TTPoE Specification
````{verbatim}
You will find the spec
In the repo "doc" folder
TTPoE
````
# ttpoe_sw

The following sections have details regarding making and executing the reference linux kernel sw model. It is matched to v1.5 of the TTP specification. Some variables may have changed slightly without documentation updates, but we're sure you can figure it out.

# TTP Kernel Module (modttpoe.ko):

GIT repo info and unit tests

The source code git repo is at https://github.com/teslamotors/ttpoe. The code for modttpoe is under the 'modttpoe' subdir. The compilation is controlled via a top level Makefile in order to allow related modules to share symbols. Compilation is done as follows (gcc, linux-5.15-0-48-generic, ubuntu22):

    $ pwd
    GIT_HEAD

    $ make all
    .... <compilation output> ....
    $ ls -l ./modttpoe/modttpoe.ko
    -rw-rw-r-- 1 user group 3456000 Jan  1 10:00 modttpoe/modttpoe.ko

    $ modinfo ./modttpoe/modttpoe.ko
    filename:       /home/dojo-user/work/git/tesla/ttpoe_sw/modttpoe/modttpoe.ko
    license:        GPL
    version:        1.0
    description:    TTP Over Ethernet
    author:         dntundlam@tesla.com
    srcversion:     547796AAC2C633E730FAF4F
    depends:
    retpoline:      Y
    name:           modttpoe
    vermagic:       6.11.0-9-generic SMP preempt mod_unload modversions
    parm:           dev:      ttp device name (required at module-load)
    parm:           dest_mac: ttp destination mac-address: e.g. dest_mac=xx:xx:xx:xx:xx:xx)
    parm:           valid:    target is valid (default=0, or 1)
    parm:           vci:      ttp conn-VCI (default=0, 1, 2)
    parm:           use_gw:   use gateway to reach target (default=0, or 1)
    parm:           nhmac:    next-hop mac address (format: xx:xx:xx:xx:xx:xx)
    parm:           ipv4:     encap mode for TTP: 0 = TTPoE, 1 = TTPoIPv4 (read-only)
    parm:           prefix:   ipv4 prefix: (A.B.C.D/N)
    parm:           ipv4_sip: ipv4 src-ip: (A.B.C.D)
    parm:           ipv4_dip: ipv4 dst-ip: (A.B.C.D)
    parm:           verbose:  kernel log verbosity level (default=(-1), 0, 1, 2, 3)
    parm:           drop_pct: packet drop percent (default=(0), [0:10])
    parm:           shutdown: modttpoe shutdown state
    parm:           stats:    ttp counters (read-only)
    parm:           target:   ttp debug target (24b hex value: e.g. target=012345 => [oui]:01:23:45)
    parm:           tag_seq:  starting value of tag seq number (default=1)
    parm:           wkstep:   ttp fsm single-step state (default=0)
                              write '0' run freely; '[1-100]' set step-size; 's' step

The repo includes a script with unit tests under the 'tests' directory, using the python unit_test framework. These tests use the 'noc_debug' interface to configure and test a set of basic functionality to serve as a suite of regression tests to run before making any changes to the source code, and when adding enhancements. It is recommended to enhance the tests when new features are added to 'modttpoe'. In additional a packet generation utility called 'trafgen' (which is part of the http://netsniff-ng.org/ tooklit) it used to some inject custom TTP packets to validate the behavior of the TTP state machine functionality.

Here is an example TTP session between two hosts: node-01 and node-02:

node-01:

    $ sudo insmod modttpoe.ko dev=veth verbose=2

    $ sudo dmesg -tw
    ttpoe_init: ttp-source:00:00:00:00:00:01 mytag:[0x0000000100000001]
           dev:veth nhmac:98:ed:5c:ff:ff:ff ipv4:0
    -------------------- Module modttpoe.ko loaded --------------------+

    $ echo 2 > /sys/module/modttpoe/parameters/target

    $ cat /proc/net/modttpoe/tags
    Tag V B VC  ST  Q X Y    mac-addr gw   rx-seq   tx-seq   ret-id   #op/nl   ------ kid -------
      2 1 0  0  OS  0 0 0    00:00:02  0        1        2        1       29   0x0000000200000002

node-02:

    $ sudo insmod modttpoe.ko dev=veth verbose=2

    $ sudo dmesg -tw
    ttpoe_init: ttp-source:98:ed:5c:00:00:02 mytag:[0x0000000200000002]
           dev:veth nhmac:98:ed:5c:ff:ff:ff ipv4:0
    -------------------- Module modttpoe.ko loaded --------------------+
	...

    $ cat /proc/net/modttpoe/tags
    Tag V B VC  ST  Q X Y    mac-addr gw   rx-seq   tx-seq   ret-id   #op/nl   ------ kid -------
      1 1 0  0  OP  0 0 0    00:00:01  0        1        2        1        0   0x0000000100000001

    $ cat /proc/net/modttpoe/ev_log
    6  off  file:line             age   vc  tag  B  state/action  event-name      opcode-name     response  dir  len  rx-seq  tx-seq     next-state  next-sef              kid.idx
    0  5    modttpoe/fsm.c:116    0     -   -    -  L_^##         TTP_LINK_UP     __int_/_none__  -         ..^  0    1       0          -           -                     0x0000000100000001.1  0
    1  4    modttpoe/fsm.c:325    0     -   -    -  <<<<<         NETWORK_PKT_TX  TTP_OPEN_ACK    -         <tx  0    1       -1         -           -                     0x0000000100000001.1  0
    2  3    modttpoe/tags.c:703   0     0   1    0  OPEN_RECD     int__ALLOC_TAG  TTP_OPEN_ACK    OPEN_ACK  0    1    -1      OPEN       CHECK_NOC   0x0000000100000001.1  0
    3  2    modttpoe/tags.c:703   0     0   0    0  CLOSED        RXQ__TTP_OPEN   __int_/_none__  __none__  0    1    1       OPEN_RECD  TAG_ALLOC   0x0000000100000001.0  0
    4  1    modttpoe/ttpoe.c:435  0     -   -    -  >>>>>         NETWORK_PKT_RX  TTP_OPEN        -         >rx  0    1       1          -           -                     0x0000000100000001.0  0
    5  0    modttpoe/ttpoe.c:781  5341  -   -    -  __up-         TTP_INIT        __int_/_none__  -         .'.  0    -1      -1         -           -                     0x0000000000000000.0  0

node-01:

    $ cat /proc/net/modttpoe/ev_log
    8  off  file:line             age    vc  tag  B  state/action  event-name         opcode-name     response  dir  len  rx-seq  tx-seq     next-state  next-sef              kid.idx
    0  7    modttpoe/fsm.c:116    0      -   -    -  L_^##         TTP_LINK_UP        __int_/_none__  -         ..^  0    1       0          -           -                     0x0000000200000002.1  0
    1  6    modttpoe/fsm.c:745    0      -   -    -  !x___         TIMER_DELETE       TTP_OPEN_ACK    -         x!   0    1       -1         -           -                     0x0000000200000002.1  0
    2  5    modttpoe/tags.c:703   0      0   2    0  OPEN_SENT     RXQ__TTP_OPEN_ACK  __int_/_none__  __none__  0    1    0       OPEN       CHECK_NOC   0x0000000200000002.1  0
    3  4    modttpoe/ttpoe.c:435  0      -   -    -  >>>>>         NETWORK_PKT_RX     TTP_OPEN_ACK    -         >rx  0    1       -1         -           -                     0x0000000200000002.1  0
    4  3    modttpoe/fsm.c:143    0      -   -    -  !S_-_         SHORT_TMR_START    __int_/_none__  -         _!   0    1       1          -           -                     0x0000000200000002.0  0
    5  2    modttpoe/fsm.c:360    0      -   -    -  <<<<<         NETWORK_PKT_TX     TTP_OPEN        -         <tx  0    1       1          -           -                     0x0000000200000002.0  0
    6  1    modttpoe/tags.c:703   0      0   2    0  CLOSED        TXQ__TTP_OPEN      TTP_OPEN        OPEN      0    0    0       OPEN_SENT  OPEN_TIMER  0x0000000200000002.0  0
    7  0    modttpoe/ttpoe.c:781  37878  -   -    -  __up-         TTP_INIT           __int_/_none__  -         .'.  0    -1      -1         -           -                     0x0000000000000000.0  0

    $ echo 'Hello Tesla' > /dev/noc_debug

    $ cat /proc/net/modttpoe/tags
    Tag V B VC  ST  Q X Y    mac-addr gw   rx-seq   tx-seq   ret-id   #op/nl   ------ kid -------
      2 1 0  0  OP  0 0 0    00:00:02  0        1        3        2      248   0x0000000200000002

    $ cat /proc/net/modttpoe/ev_log
    17  off  file:line             age     vc  tag  B  state/action  event-name         opcode-name     response  dir  len  rx-seq  tx-seq     next-state  next-sef              kid.idx
    0   16   modttpoe/fsm.c:789    0       -   -    -  -free         NOC_PAYLOAD_FREE   TTP_ACK         -         -fr  0    0       -1         -           -                     0x0000000200000002.2  1
    1   15   modttpoe/fsm.c:767    0       -   -    -  !x___         TIMER_DELETE       TTP_ACK         -         x!   0    2       -1         -           -                     0x0000000200000002.4  0
    2   14   modttpoe/tags.c:703   0       0   2    0  OPEN          RXQ__TTP_ACK       __int_/_none__  __none__  0    2    0       __stay__   __none__    0x0000000200000002.4  0
    3   13   modttpoe/ttpoe.c:435  0       -   -    -  >>>>>         NETWORK_PKT_RX     TTP_ACK         -         >rx  0    2       -1         -           -                     0x0000000200000002.4  0
    4   12   modttpoe/fsm.c:611    0       -   -    -  !L_-_         LONG_TMR_START     __int_/_none__  -         !!   0    0       2          -           -                     0x0000000200000002.3  0
    5   11   modttpoe/fsm.c:601    0       -   -    -  <<<<<         NETWORK_PKT_TX     TTP_PAYLOAD     -         <tx  12   0       2          -           -                     0x0000000200000002.3  0
    6   10   modttpoe/tags.c:703   0       0   2    0  OPEN          TXQ__TTP_PAYLOAD   TTP_PAYLOAD     PAYLOAD   12   0    2       __stay__   __none__    0x0000000200000002.3  2
    7   9    modttpoe/tags.c:1056  0       -   -    -  <<-vv         NOC_PAYLOAD_ENQ    TTP_PAYLOAD     -         -vv  12   0       2          -           -                     0x0000000200000002.2  1
    8   8    modttpoe/noc.c:256    0       -   -    -  vvvvv         NOC_PAYLOAD_TX     TTP_PAYLOAD     -         -tx  12   0       0          -           -                     0x0000000200000002.2  1
    9   7    modttpoe/fsm.c:116    188553  -   -    -  L_^##         TTP_LINK_UP        __int_/_none__  -         ..^  0    1       0          -           -                     0x0000000200000002.1  0
    10  6    modttpoe/fsm.c:745    0       -   -    -  !x___         TIMER_DELETE       TTP_OPEN_ACK    -         x!   0    1       -1         -           -                     0x0000000200000002.1  0
    11  5    modttpoe/tags.c:703   0       0   2    0  OPEN_SENT     RXQ__TTP_OPEN_ACK  __int_/_none__  __none__  0    1    0       OPEN       CHECK_NOC   0x0000000200000002.1  0
    12  4    modttpoe/ttpoe.c:435  0       -   -    -  >>>>>         NETWORK_PKT_RX     TTP_OPEN_ACK    -         >rx  0    1       -1         -           -                     0x0000000200000002.1  0
    13  3    modttpoe/fsm.c:143    0       -   -    -  !S_-_         SHORT_TMR_START    __int_/_none__  -         _!   0    1       1          -           -                     0x0000000200000002.0  0
    14  2    modttpoe/fsm.c:360    0       -   -    -  <<<<<         NETWORK_PKT_TX     TTP_OPEN        -         <tx  0    1       1          -           -                     0x0000000200000002.0  0
    15  1    modttpoe/tags.c:703   0       0   2    0  CLOSED        TXQ__TTP_OPEN      TTP_OPEN        OPEN      0    0    0       OPEN_SENT  OPEN_TIMER  0x0000000200000002.0  0
    16  0    modttpoe/ttpoe.c:781  37878   -   -    -  __up-         TTP_INIT           __int_/_none__  -         .'.  0    -1      -1         -           -                     0x0000000000000000.0  0

node-02:

    $ cat /proc/net/modttpoe/tags
    Tag V B VC  ST  Q X Y    mac-addr gw   rx-seq   tx-seq   ret-id   #op/nl   ------ kid -------
      1 1 0  0  OP  0 0 0    00:00:01  0        2        2        1        0   0x0000000100000001

    $ cat /dev/noc_debug
    Hello Tesla

    $ cat /proc/net/modttpoe/ev_log
    10  off  file:line             age     vc  tag  B  state/action  event-name        opcode-name     response  dir  len  rx-seq  tx-seq     next-state  next-sef              kid.idx
    0   9    modttpoe/fsm.c:544    0       -   -    -  <<<<<         NETWORK_PKT_TX    TTP_ACK         -         <tx  0    2       -1         -           -                     0x0000000100000001.2  0
    1   8    modttpoe/fsm.c:500    0       -   -    -  ^^^^^         NOC_PAYLOAD_RX    TTP_ACK         -         -rx  0    0       -1         -           -                     0x0000000100000001.2  0
    2   7    modttpoe/tags.c:703   0       0   1    0  OPEN          RXQ__TTP_PAYLOAD  TTP_ACK         ACK       0    0    -1      __stay__   __none__    0x0000000100000001.2  0
    3   6    modttpoe/ttpoe.c:435  0       -   -    -  >>>>>         NETWORK_PKT_RX    TTP_PAYLOAD     -         >rx  12   0       2          -           -                     0x0000000100000001.2  0
    4   5    modttpoe/fsm.c:116    188552  -   -    -  L_^##         TTP_LINK_UP       __int_/_none__  -         ..^  0    1       0          -           -                     0x0000000100000001.1  0
    5   4    modttpoe/fsm.c:325    0       -   -    -  <<<<<         NETWORK_PKT_TX    TTP_OPEN_ACK    -         <tx  0    1       -1         -           -                     0x0000000100000001.1  0
    6   3    modttpoe/tags.c:703   0       0   1    0  OPEN_RECD     int__ALLOC_TAG    TTP_OPEN_ACK    OPEN_ACK  0    1    -1      OPEN       CHECK_NOC   0x0000000100000001.1  0
    7   2    modttpoe/tags.c:703   0       0   0    0  CLOSED        RXQ__TTP_OPEN     __int_/_none__  __none__  0    1    1       OPEN_RECD  TAG_ALLOC   0x0000000100000001.0  0
    8   1    modttpoe/ttpoe.c:435  0       -   -    -  >>>>>         NETWORK_PKT_RX    TTP_OPEN        -         >rx  0    1       1          -           -                     0x0000000100000001.0  0
    9   0    modttpoe/ttpoe.c:781  5341    -   -    -  __up-         TTP_INIT          __int_/_none__  -         .'.  0    -1      -1         -           -                     0x0000000000000000.0  0

# Built-in unit-tests for modttpoe:

    $ ./tests/run.sh --target=2 -v
    v---------------------------------------v
     Start tests: 2024-10-10 10:00:00.000000
       TTP Encap: ttpoe (etype: 0x9ac6)
        Self MAC: 98:ed:5c:00:00:01
     Self Target: 000001
       Self Host: node-01
        Peer MAC: 98:ed:5c:00:00:02
     Peer Target: 000002
       Peer Host: node-02
     Use Gateway: False
    test1_seq_clr (__main__.Test0_Seq_IDs.test1_seq_clr) ... ok
    test2_tx1_seq (__main__.Test0_Seq_IDs.test2_tx1_seq) ... ok
    test3_rx1_seq (__main__.Test0_Seq_IDs.test3_rx1_seq) ... ok
    test4_tx2_seq (__main__.Test0_Seq_IDs.test4_tx2_seq) ... ok
    test1_proc_stats (__main__.Test1_Proc.test1_proc_stats) ... ok
    test2_ttpoe_tags (__main__.Test1_Proc.test2_ttpoe_tags) ... ok
    test3_debug__500 (__main__.Test1_Proc.test3_debug__500) ... ok
    test4_debug_1000 (__main__.Test1_Proc.test4_debug_1000) ... ok
    test5_debug_2000 (__main__.Test1_Proc.test5_debug_2000) ... ok
    test6_debug_3000 (__main__.Test1_Proc.test6_debug_3000) ... ok
    test7_debug_4000 (__main__.Test1_Proc.test7_debug_4000) ... ok
    test1_get_open (__main__.Test2_Packet.test1_get_open) ... ok
    test2_snd_open (__main__.Test2_Packet.test2_snd_open) ... ok
    test3_get_pyld (__main__.Test2_Packet.test3_get_pyld) ... ok
    test4_snd_pyld (__main__.Test2_Packet.test4_snd_pyld) ... ok
    test5_get_clos (__main__.Test2_Packet.test5_get_clos) ... ok
    test6_snd_clos (__main__.Test2_Packet.test6_snd_clos) ... ok
    test1_show_tag (__main__.Test3_Noc_db.test1_show_tag) ... ok
    test2_show_dbg (__main__.Test3_Noc_db.test2_show_dbg) ... ok
    test1_traffic (__main__.Test4_Traffic.test1_traffic) ... ok
    test2_traffic (__main__.Test4_Traffic.test2_traffic) ... ok
    test3_traffic (__main__.Test4_Traffic.test3_traffic) ... ok
    test4_traffic (__main__.Test4_Traffic.test4_traffic) ... ok
    test5_traffic (__main__.Test4_Traffic.test5_traffic) ... ok
    test1_cleanup (__main__.Test5_Cleanup.test1_cleanup) ... ok
    test2_cleanup (__main__.Test5_Cleanup.test2_cleanup) ... ok
    test3_cleanup (__main__.Test5_Cleanup.test3_cleanup) ... ok
    
    ----------------------------------------------------------------------
    Ran 27 tests in 14.301s
    
    OK

# TTP Gateway Module (modttpip.ko):

Currently there are no unit-tests for the TTP gateway.
The module 'modttpip' has configuration parameters, some of which must be specified on the command line during insmod:


    $ modinfo modttpip/modttpip.ko
    filename:       /home/dojo-user/work/git/tesla/ttpoe_sw/modttpip/modttpip.ko
    license:        GPL
    version:        1.0
    description:    TTP IP Gateway
    author:         dntundlam@tesla.com
    srcversion:     FCBBF59CD1A10DCE72F2936
    depends:
    retpoline:      Y
    name:           modttpip
    vermagic:       6.11.0-9-generic SMP preempt mod_unload modversions
    parm:           gwips:    set list of ttp gateway ip-addreses per zone (1,2,3,..):
                              e.g. gwips=10.0.1.1,10.0.2.2,10.0.3.3,..
    parm:           intfs:    get all interfaces on the ttp-gateway
    parm:           edevs:    get all devices on the ttp-gateway
    parm:           dev:      ttp device name (required at module-load)
    parm:           mactbl:   read gateway mac-address table
    parm:           drop_pct: packet drop percent (default=(0), [0:10])
    parm:           shutdown: modttpoe shutdown state
    parm:           verbose:  kernel log verbosity level (default=(-1), 0, 1, 2, 3)

    $ sudo insmod modttpip.ko dev=veth gwips=192.168.80.10,192.168.80.20,192.168.30.30 verbose=1

    $ sudo dmesg -tw
    ttp_param_gwips_set: Parsing gwips from '192.168.80.10,192.168.80.20,192.168.30.30'
    `->: Zeroed out 64 bytes: 8 ttp_zones
      `->zn:1 ip4:192.168.80.10
      `->zn:2 ip4:192.168.80.20
      `->zn:3 ip4:192.168.30.30
    ttp_param_gwips_set: Scanning network devices:
    `->Found device: dev:ens20 id:4 mac:bc:24:11:b8:94:64
      `->Scanning ipv4 addresses: on dev:ens20
        `->ipv4:192.168.80.10/24
          `->Found zone: my_zn:1 dev:ens20 ip4:192.168.80.10/24
    ttpip_init: ip4-if:'ens20' mac:bc:24:11:b8:94:64
                ttp-if:'vleth' mac:bc:24:11:23:48:45
    ------------------ Module modttpip.ko loaded -----------------+
      `->zn:2 gw:192.168.80.20 -> mac:bc:24:11:f8:e6:de
        `->via:dir-arp:192.168.80.20 -> dev:ens20
      `->zn:3 gw:192.168.30.30 -> mac:fa:df:59:d6:41:8d
        `->via:rt-v4:192.168.80.1 -> dev:ens20
    ttp_nh_mac_tmr_cb: resolved all nh-macs

    $ ls -l /sys/module/modttpip/parameters
    -r--r--r-- 1 root root 4096 Nov 13 15:58 dev
    -rw-r--r-- 1 root root 4096 Nov 13 15:58 drop_pct
    -r--r--r-- 1 root root 4096 Nov 13 15:58 edevs
    -rw-r--r-- 1 root root 4096 Nov 13 15:58 gwips
    -r--r--r-- 1 root root 4096 Nov 13 15:58 intfs
    -r--r--r-- 1 root root 4096 Nov 13 15:53 mactbl
    -rw-r--r-- 1 root root 4096 Nov 13 15:58 shutdown
    -rw-r--r-- 1 root root 4096 Nov 13 15:58 verbose

There are no runtime configurable parameters in modttpip. Unloading modttpip is done as follows:

    $ sudo rmmod modttpip
    $ sudo dmesg -tw
    ttpip: ~~~~~~~~~~~~~~~~~~~~~ Module modttpip.ko unloaded ~~~~~~~~~~~~~~~~~~~~~+

