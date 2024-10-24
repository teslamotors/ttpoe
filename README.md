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

# modttpoe.ko:

GIT repo info and unit tests

The source code git repo is at https://github.com/teslamotors/ttpoe. The code for modttpoe is under the 'modttpoe' subdir. The compilation is controlled via a top level Makefile in order to allow related modules to share symbols. Compilation is done as follows (gcc, linux-5.15-0-48-generic, ubuntu22):

    $ pwd
    GIT_HEAD

    $ make all
    .... <compilation output> ....
    $ ls -l ./modttpoe/modttpoe.ko
    -rw-rw-r-- 1 user group 2676144 Jan  1 10:00 modttpoe/modttpoe.ko

    $ modinfo ./modttpoe/modttpoe.ko
    filename:       GIT_HEAD/./modttpoe/modttpoe.ko
    license:        GPL
    version:        eng0.2402.8
    description:    TTP Over Ethernet
    author:         dojo-user@tesla.com
    srcversion:     862A3F5D98811A48B65F0CD
    depends:
    retpoline:      Y
    name:           modttpoe
    vermagic:       5.15.0-97-generic SMP mod_unload modversions
    parm:           target:   ttp target (24b hex value: e.g. target=0x012345 => 98:ed:5c:01:23:45)
    parm:           vci:      ttp conn-VCI (default=0, 1, 2)
    parm:           stats:    ttp counters (read-only)
    parm:           wkstep:   modttpoe fsm single-step state (default=0)
                              write '0' run freely; '[1-100]' set step-size; 's' step
    parm:           dev:      ttp device name (required at module-load)
    parm:           shutdown: modttpoe shutdown state (read-only)
    parm:           verbose:  kernel log verbosity level (default=0, 1, 2)
    parm:           tag_seq:  starting value of tag seq number (default=1)


The repo includes a script with unit tests under the 'tests' directory, using the python unit_test framework. These tests use the 'noc_debug' interface to configure and test a set of basic functionality to serve as a suite of regression tests to run before making any changes to the source code, and when adding enhancements. It is recommended to enhance the tests when new features are added to 'modttpoe'. In additional a packet generation utility called 'trafgen' (which is part of the http://netsniff-ng.org/ tooklit) it used to some inject custom TTP packets to validate the behavior of the TTP state machine functionality.

Here is an example TTP session between two hosts: node-01 and node-02:

Node-01:

    $ sudo insmod modttpoe.ko dev=vl100 verbose=2

    $ sudo dmesg
    [529240.838851] ttpoe: ttp-source: 98:ed:5c:00:00:01  [0x0000000100000001]  device: vl100
    [529240.838890] ttpoe: ~~~~~~~~~~~~~~~~~~~~~ Module modttpoe.ko loaded ~~~~~~~~~~~~~~~~~~~~~+

    $ echo 2 | sudo tee /sys/module/modttpoe/parameters/target

    $ cat /proc/net/modttpoe/tags
    tag table: bkt0(1) ++(1) (0)--   bkt1(0) ++(0) (0)--   colls(0)
    tag  B  V  ST  Q X Y G   vc  mac addr   len   rx-seq   tx-seq   ------- kid --------  mark
      2  0  1  CC  0 0 0 0    0  00:00:02    --        0        1   0x0000000200000002

Node-02:

    $ sudo insmod modttpoe.ko dev=vl100 verbose=2

    $ sudo dmesg
    [529348.804309] ttpoe: ttp-source: 98:ed:5c:00:00:02  [0x0000000200000002]  device: vl100
    [529348.804360] ttpoe: ~~~~~~~~~~~~~~~~~~~~~ Module modttpoe.ko loaded ~~~~~~~~~~~~~~~~~~~~~+

    $ echo 1 | sudo tee /sys/module/modttpoe/parameters/target

    $ cat /proc/net/modttpoe/tags
    tag table: bkt0(1) ++(1) (0)--   bkt1(0) ++(0) (0)--   colls(0)
    tag  B  V  ST  Q X Y G   vc  mac addr   len   rx-seq   tx-seq   ------- kid --------  mark
      1  0  1  CC  0 0 0 0    0  00:00:01    --        0        1   0x0000000100000001

    $ echo 'Hello Tesla' | sudo tee /sys/kernel/debug/modttpoe/noc_debug

    $ cat /proc/net/modttpoe/tags
    tag table: bkt0(1) ++(1) (0)--   bkt1(0) ++(0) (0)--   colls(0)
    tag  B  V  ST  Q X Y G   vc  mac addr   len   rx-seq   tx-seq   ------- kid --------  mark
      1  0  1  OO  0 0 0 0    0  00:00:01    --        1        3   0x0000000100000001

Node-01:

    $ cat /proc/net/modttpoe/tags
    tag table: bkt0(1) ++(1) (0)--   bkt1(0) ++(0) (0)--   colls(0)
    tag  B  V  ST  Q X Y G   vc  mac addr   len   rx-seq   tx-seq   ------- kid --------  mark
      2  0  1  OO  0 0 0 0    0  00:00:02    --        2        2   0x0000000200000002

    $ cat /proc/net/modttpoe/noc_debug
    Hello Tesla

    # modttpip.ko:

    $ ls -l ./modttpip/modttpip.ko
    -rw-rw-r-- 1 user group 652120 Jan  1 10:00 modttpoe/modttpip.ko

    $ modinfo ./modttpip/modttpip.ko
    filename:       GIT_HEAD/./modttpip/modttpip.ko
    license:        GPL
    version:        eng0.2402.8
    description:    TTP IP Gateway
    author:         dojo-user@tesla.com
    srcversion:     0AD10BA371ADCCD35143E3A
    depends:
    retpoline:      Y
    name:           modttpip
    vermagic:       5.15.0-97-generic SMP mod_unload modversions
    parm:           gwips:    set list of ttp gateway ip-addreses per zone (1,2,3,..):
                              `e.g. gwips=192.168.80.10,192.168.80.20,192.168.70.30
    parm:           mactbl:   read gateway mac-address table; write triggers refresh
    parm:           dev:      ttp device name (required at module-load)
    parm:           shutdown: modttpoe shutdown state (read-only)
    parm:           verbose:  kernel log verbosity level (default=0, 1, 2)

Currently there are no unit-tests for the TTP gateway.

The module 'modttpip' has configuration parameters, some of which must be specified on the command line during insmod:

    $ sudo insmod modttpip.ko dev=vl100 gwips=192.168.80.10,192.168.80.20,192.168.70.30 verbose=1

    $ sudo lsmod | grep ttp
    modttpip               24576  0

    $ sudo dmesg -t
    ttpip: ttp_param_gwips_set: zn: 1 ip: 192.168.80.10
    ttpip: ttp_param_gwips_set: zn: 2 ip: 192.168.80.20
    ttpip: ttp_param_gwips_set: zn: 3 ip: 192.168.70.30
    ttpip: ttpip_init: dev:  ens20  ip: 192.168.80.10    mask: 255.255.255.0
    ttpip: `-> found my-zone: 1
    ttpip: ttpip_init: dev:  vl100  ip: none  (dev)
    ttpip: zn: 1 gw: 192.168.80.10  (myself)
    ttpip: zn: 2 gw: 192.168.80.20  via: device ' ens20' arp: bc:24:11:f8:e6:de
    ttpip: zn: 3 gw: 192.168.70.30  via: 192.168.80.1  route: 3c:ec:ef:dc:e4:cc
    ttpip: ttp_mac_table_populate: found 3 mac-addresses
    ttpip: ttpip_init: 'ens20': bc:24:11:b8:94:64  'vl100': 98:ed:5c:01:00:00
    ttpip: ---------------------- Module modttpip.ko loaded ----------------------+

    $ sudo cd /sys/module/modttpip/parameters

    $ sudo ls -l
    -r--r--r-- 1 root root 4096 Jan 10 01:32 dev
    -r--r--r-- 1 root root 4096 Jan 10 01:32 gwips
    -rw-r--r-- 1 root root 4096 Jan 10 01:32 mactbl
    -rw-r--r-- 1 root root 4096 Jan 10 01:32 shutdown
    -rw-r--r-- 1 root root 4096 Jan 10 01:32 verbose

There are no runtime configurable parameters in modttpip. Unloading modttpip is done as follows:

    $ sudo rmmod modttpip

    $ sudo dmesg -t
    ttpip: ~~~~~~~~~~~~~~~~~~~~~ Module modttpip.ko unloaded ~~~~~~~~~~~~~~~~~~~~~+

