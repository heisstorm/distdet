#!/usr/bin/env bash

IP_LIST=(google.com baidu.com yahoo.com zhihu.com youtube.com facebook.com twitter.com amazon.com apple.com quora.com)

for ip in ${IP_LIST[*]}
    do ping -c 1 $ip
    done