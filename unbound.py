#! /usr/bin/env python3

import os, sys


header = False
for ll in sys.stdin:
    ll = ll.strip()
    if len(ll) == 0:       continue
    if ll.startswith('#'):
        print(ll)
        continue

    if not header:
        print("server:")
        header = True

    print(f'local-zone: "{ll}" static')


