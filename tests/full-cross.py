#!/usr/bin/python3

# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2023 Tesla Inc. All rights reserved.
#
# TTP (TTPoE) A reference implementation of Tesla Transport Protocol (TTP) that runs
#             directly over Ethernet Layer-2 Network. This is implemented as a Loadable
#             Kernel Module that establishes a TTP-peer connection with another instance
#             of the same module running on another Linux machine on the same Layer-2
#             network. Since TTP runs over Ethernet, it is often referred to as TTP Over
#             Ethernet (TTPoE). This is a test script.
#
#             This public release of the TTP software implementation is aligned with the
#             patent disclosure and public release of the main TTP Protocol
#             specification. Users of this software module must take into consideration
#             those disclosures in addition to the license agreement mentioned here.
#
# Authors:    Diwakar Tundlam <dntundlam@tesla.com>
#
# This software is licensed under the terms of the GNU General Public License version 2
# as published by the Free Software Foundation, and may be copied, distributed, and
# modified under those terms.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; Without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE. See the GNU General Public License for more details.

import sys
import time
import random
import argparse
import subprocess
from   contextlib import redirect_stdout

zons = [[0x1,  0x2,  0x3],
        [0x4,  0x5,  0x6],
        [0x7,  0x8,  0x9],
        [0xa,  0xb,  0xc]]

zu20 = [0x10, 0x11]             # ub20 nodes (--u20)
zutm = [0x21, 0x22, 0x23, 0x24] # utm  nodes (--utm)

# Functional variables
totn = 0
runs = []
ktst = ""

# Unicode stop, play, pause icons
done = '⏹'
runn = '⏵'
paus = '⏸'
dott = '‥'

# Colors for output
gray:    str = "\033[30m"
red:     str = "\033[31m"
green:   str = "\033[32m"
yellow:  str = "\033[33m"
blue:    str = "\033[34m"
magenta: str = "\033[35m"
cyan:    str = "\033[36m"
white:   str = "\033[37m"
clear:   str = "\033[00m"

def cursor_visible (yes: bool):
    if yes:
        print('\033[?25h', end="")
    else:
        print ('\033[?25l', end="")

# Function to generate random runs without repetition
def gen_unique_random_runs (lists):
    # Flatten lists and keep track of original indexes
    itms = [(itm, idx) for idx, lst in enumerate (lists) for itm in lst]
    random.shuffle (itms)

    while len (itms) >= 2: # Try to form runs
        itm1, idx1 = itms.pop()
        itm2, idx2 = None, None

        for iv in range( len (itms)): # Find valid 2nd item from next list
            itm2, idx2 = itms[iv]
            if idx1 != idx2:
                break
        if idx1 == idx2:
            return False

        # Do not initiate test from {node-10 or node-11} as it always fails
        if (itm1 == 0x10 and itm2 == 0x11) or (itm1 == 0x11 and itm2 == 0x10):
            return False
        elif itm1 == 0x10 or itm1 == 0x11:
            runs.append ((itm2, itm1))
        else:
            runs.append ((itm1, itm2))
        itms.pop (iv) # Remove 2nd item from list

    return True

def setup_test():
    if not gen_unique_random_runs (zons):
        if not options.quiet:
            print (f" {red}Failed to generate {int(totn/2)} tests:"
                   f" try again!{clear}")
        return False
    else:
        with open('/tmp/fxrun.sh', 'w') as f:
            with redirect_stdout(f):
                print ("#!/bin/bash\n")
                print (f"# Generated '{len(runs)}' tests:\n")
                for ri in runs:
                    if not options.quiet:
                        print ("(ssh node-%02x /mnt/mac/tests/run.sh --target=%02x"
                               f" --use-gw {ktst} 2>/dev/null 1>/dev/null"
                               " && echo '  %d: node-%02x <-> node-%02x"
                               f" [{green}ok{clear}]'"
                               " || echo '  %d: node-%02x <-> node-%02x"
                               f" [{red}fail{clear}]') %s"
                               % (ri[0], ri[1],
                                  runs.index(ri)+1, ri[1], ri[0],
                                  runs.index(ri)+1, ri[0], ri[1],
                                  "&" if prll else ""))
                    else:
                        print ("(ssh node-%02x /mnt/mac/tests/run.sh --target=%02x"
                               f" --use-gw {ktst} 2>/dev/null 1>/dev/null) %s"
                               % (ri[0], ri[1], "&" if prll else ""))
                if prll:
                    if not options.quiet:
                        print (f"\necho '   Start {len(runs)} tests; Wait to end'\n")
                    else:
                        print (f"\n#echo '   Start {len(runs)} tests; Wait to end'\n")
                print ("wait\n")
        subprocess.run (["chmod", "755", "/tmp/fxrun.sh"])
        if not options.quiet:
            print (f" {green}Generated {len(runs)} tests:{clear}")
        if options.verbose:
            for ri in runs:
                print ("  %d: node-%02x <-> node-%02x [%ssetup%s]"
                       % (runs.index(ri)+1, ri[0], ri[1], green, clear))
        return True

def run_test (rn, mx):
    if dryr:
        print (f" {yellow}Dry-run# {rn}/{mx} ----------------------{clear}")
        print (f"  {magenta} Saved file '/tmp/fxrun.sh'")
        if not options.quiet:
            print (f"   Simulate test-run (sleep for {slpt} sec){clear}")
        time.sleep (slpt)
        return
    if not options.quiet:
        print (f" {cyan}Run# {rn}/{mx} ----------------------{clear}")
        print (f"  Run {len(runs)} tests "
               f"[{"parallel" if prll else "serial"}]"
               f"{clear}")
    else:
        print (f" test [{(rn -1) * done}{runn}{(mx - rn) * dott}] {rn}/{mx}",
               end="\r", flush=True)
    subprocess.run (["/tmp/fxrun.sh"])
    subprocess.run (["rm", "-f", "/tmp/fxrun.sh"])
    if options.quiet and rn == mx:
        print (f" done [{rn * done}{(mx - rn) * dott}] {rn}/{mx}",
               end="\n", flush=True)

if __name__ == '__main__':
    cursor_visible (False)
    # define cmdline options
    parser = argparse.ArgumentParser()
    parser.add_argument ('-a', '--all', action='store_true',
                         help='equivalent to -cub -n5 -w10')
    parser.add_argument ('-b', '--b20', action='store_true',
                         help='include uBuntu20 nodes [10,11]')
    parser.add_argument ('-c', '--clr', action='store_true',
                         help='clears screen before each run')
    parser.add_argument ('-d', '--dry', action='store_true',
                         help='dry-run: saves cmd file (ignores --num/-n)')
    parser.add_argument ('-m', '--min', action='store_true',
                         help='minimum test: \'just run: -k Test0\'')
    parser.add_argument ('-n', '--num',
                         help='number of repetitions')
    parser.add_argument ('-q', '--quiet', action='store_true',
                         help='succeeds quietly: reports failures ')
    parser.add_argument ('-s', '--ser', action='store_true',
                         help='run tests in serial (default: parallel)')
    parser.add_argument ('-u', '--utm', action='store_true',
                         help='include UTM nodes [21,..,24]')
    parser.add_argument ('-v', '--verbose', action='store_true',
                         help='verbose output: (overrides --quiet/-q)')
    parser.add_argument ('-w', '--wait',
                         help='wait time between tests (default: 10sec)')

    # parse cmdline options
    options, args = parser.parse_known_args()
    sys.argv[1:] = args

    # --all (-a) processing
    nrun = 5 if options.all else 1 # default value
    clrs = options.all
    if options.all:
        zons.append (zutm)
        zons[0].append (zu20[0])
        zons[1].append (zu20[1])

    # other options processing
    prll = not options.ser
    dryr = options.dry
    clrs = options.clr or options.all
    nrun = int(options.num) if options.num else nrun
    slpt = int(options.wait) if options.wait else 10 # default value

    if options.verbose:
        options.quiet = False

    # include nodes as specified
    if options.utm:
        zons.append (zutm)
    if options.b20:
        zons[0].append (zu20[0])
        zons[1].append (zu20[1])

    if options.min:
        ktst = "-k Test0"

    # begin
    subprocess.run (["clear"]) if clrs else None

    for zn in zons:
        totn += len(zn)
    if totn % 2:
        totn = totn-1
    if dryr:
        nrun = 1
        slpt = 0.25
    for xn in range (nrun):
        if not options.quiet:
            print (f"{blue}Cross-test: Nodes:{totn} Zones:{len(zons)}{clear}") \
                if nrun == 1 else \
                   print (f"{blue}Cross-tests: Runs:{nrun} Nodes:{totn} "
                          f"Zones:{len(zons)}{clear}")
        runs = [] # refresh
        while not setup_test():
            runs = [] # refresh
        try:
            run_test (xn+1, nrun)
        except:
            print (f" {red}Run interrupted! cleanup may be needed{clear}")
            cursor_visible (True)
            sys.exit(-1)
        if xn < (nrun-1):
            if not options.quiet:
                print()
                print (f" {blue} Wait for {slpt}sec....{clear}")
            else:
                print (f" wait [{(xn +1) * done}{paus}{(nrun - xn -2) * dott}]"
                       f" {xn +1}/{nrun}", end="\r", flush=True)
            try:
                time.sleep (slpt)
            except:
                cursor_visible (True)
                sys.exit(0)
            subprocess.run (["clear"]) if clrs else None
    cursor_visible (True)
