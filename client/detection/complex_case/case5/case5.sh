#!/usr/bin/env bash

IP_LIST=(google.com baidu.com yahoo.com zhihu.com youtube.com facebook.com twitter.com amazon.com apple.com quora.com)

for ip in ${IP_LIST[*]}
    do ping -c 1 $ip
    done

wget https://www.dropbox.com/s/ikhqu93oahk9dk0/sysrep_random_data?dl=0
python3 /home/pxf109/Reptracker/sysrep_case_scripts/case5/read_exp_data.py
