#!/usr/bin/env bash

IP_LIST=(google.com baidu.com yahoo.com zhihu.com youtube.com facebook.com twitter.com amazon.com apple.com quora.com)

for ip in ${IP_LIST[*]}
    do wget $ip
    done
wget https://www.dropbox.com/s/ikhqu93oahk9dk0/sysrep_random_data?dl=0
mv $PWD/sysrep_random_data?dl=0 $PWD/hide_file.txt
