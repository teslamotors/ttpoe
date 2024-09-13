#!/usr/bin/python3

import sys
import os
import time
import subprocess
import argparse
from datetime import datetime

pf = open ("/mnt/mac/evlog")

for ln in pf.read().split('\n'):
    lp = ln.split()
    print (",".join(lp))
