#!/usr/bin/python3

import random
import subprocess
from   contextlib import redirect_stdout

zons = [[0x1,  0x2,  0x3],        # zone-1
        [0x4,  0x5,  0x6],        # zone-2
        [0x7,  0x8,  0x9],        # zone-3
        [0xa,  0xb,  0xc],        # zone-4
#       [0xd,  0xe,  0xf],        # zone-5
#       [0x21, 0x22, 0x23, 0x24], # zone-6
        ]
totn = 0
used = []
runs = []

def comm (itr):
    for ix in range (len(zons)):
        for iy in range (len(zons[ix])):
            itr %= len(zons[iy])
            if iy == ix or zons[ix][iy] == zons[iy][itr]:
                continue;
            if zons[ix][iy] not in used and zons[iy][itr] not in used:
                used.append (zons[ix][iy])
                used.append (zons[iy][itr])
                runs.append ([zons[ix][iy], zons[iy][itr]])
                if len(runs) > (totn / 2):
                    return
                break

def run_test (nn, nx):
    subprocess.run (["date", f"+Run {nn}/{nx}: %T %F"])
    for iv in range (100):
        random.shuffle (zons)
        comm (iv)
        if len(runs) > (totn / 2):
            break
    if len(runs) < (totn / 2):
        return
    print (f" Permuted {len(runs)} commands:")
    for rn in runs:
        print ("  %d: node-%02x <--> node-%02x" % (runs.index(rn) + 1, rn[0], rn[1]))
    with open('/tmp/fxrun.sh', 'w') as f:
        with redirect_stdout(f):
            print ("#!/bin/bash\n")
            print (f"# Permuted {len(runs)} commands:-\n")
            for rn in runs:
                print ("ssh node-%02x /mnt/mac/tests/run.sh --target=%02x --use-gw"
                       " > /tmp/log-%02x%02x.txt &" % (rn[0], rn[1], rn[0], rn[1]))
            print ("\nwait\n")
    subprocess.run (["chmod", "755", "/tmp/fxrun.sh"])
    subprocess.run (["/tmp/fxrun.sh"])
    subprocess.run (["rm", "-f", "/tmp/fxrun.sh"])
    print ()

if __name__ == '__main__':
    for zn in zons:
        totn += len(zn)
    num = 2
    print (f"Cross-tests: {num} runs against {totn} nodes in {len(zons)} zones")
    for ni in range (num):
        run_test (ni + 1, num)
