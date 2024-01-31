# -* - coding: UTF-8 -* -
# ! /usr/bin/python
import time
import subprocess
import os

# sysdig 是滚动运行的

if __name__ == '__main__':
    # sysdig_command = 'nohup sysdig -p"%evt.num %evt.rawtime.s.%evt.rawtime.ns %evt.cpu %proc.name (%proc.pid) %evt.dir %evt.type cwd=%proc.cwd %evt.args latency=%evt.latency" -s 200 evt.type!=switch and proc.name!=sysdig -A -w system_log.scap -G 60 &'
    # process_sys = subprocess.Popen(sysdig_command, shell=True)
    while True:
        current_file = "system_log.scap-1"
        for filename in sorted(os.listdir(".")):
            if "system_log.scap" in filename:
                current_file = filename
                current_size_pre = os.path.getsize(current_file)
                time.sleep(1)
                current_size_post = os.path.getsize(current_file)
                if current_size_pre != current_size_post:
                    current_file = "system_log.scap-1"
                    continue
                else:
                    break
        if current_file != "system_log.scap-1":
            current_file_txt = current_file.replace("scap", "txt")
            print("processing " + current_file)
            sysdig_command = "sysdig -r %s > %s" % (current_file, current_file_txt)
            process_sys = subprocess.Popen(sysdig_command, shell=True)
            hst_anlysis_command = 'python3 HST.py %s' % current_file_txt
            subprocess.Popen(hst_anlysis_command, shell=True)
            print("processed " + current_file)
            time.sleep(30)
            os.remove(current_file)
            os.remove(current_file_txt)
            print("removed " + current_file)
        else:
            time.sleep(30)
