# -* - coding: UTF-8 -* -
# ! /usr/bin/python
import time
import subprocess
import os
import re

# sysdig 是滚动运行的

if __name__ == '__main__':
    input_string1 = "6(shijielu) flags=0 cap_inheritable=0 cap_permitted=0 cap_effective=0 exe_ino=42598935 exe_ino_ctime=2023-05-03 10:14:29.28654218 exe_ino_mtime=2019-09-05 03:38:40.00000000 uid=1941350626(shijielu) trusted_exepath=/usr/bin/head "
    input_string = "tid=2986028(sleep) pid=2986028(sleep) ptid=2985433(bash) cwd=<NA> fdlimit=1024 pgft_maj=0 pgft_min=24 vm_size=384 vm_rss=4 vm_swap=0 comm=sleep cgroups=cpuset=/.cpu=/user.slice.cpuacc626(shijielu) trusted_exepath=/usr/bin/sleep "
    pattern = r'trusted_exepath=([^ ]+)'
    match = re.search(pattern, input_string)
    if match:
        trusted_exepath = match.group(1)
        print(trusted_exepath)