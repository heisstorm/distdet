import schedule
import subprocess
import time

sysdig_output = "system_log_a.txt"
# 主被倒换
def run_command():
    global sysdig_output
    if sysdig_output == "system_log_a.txt":
        sysdig_output = "system_log_b.txt"
        hst_anlysis = "system_log_a.txt"
    else:
        sysdig_output = "system_log_a.txt"
        hst_anlysis = "system_log_b.txt"
    hst_anlysis_command = 'python3 HST.py %s' % hst_anlysis
    print(hst_anlysis_command)
    print(time.time())
    subprocess.Popen(hst_anlysis_command, shell=True)
    sysdig_command = 'sysdig -p"%evt.num %evt.rawtime.s.%evt.rawtime.ns %evt.cpu %proc.name (%proc.pid) %evt.dir %evt.type cwd=%proc.cwd %evt.args latency=%evt.latency" -s 200 evt.type!=switch and proc.name!=sysdig > ' + sysdig_output
    print(sysdig_command)
    print(time.time())
    process_sys = subprocess.Popen(sysdig_command, shell=True)
    # 这里依旧不对，hst还是等sysdig跑完再开始的，所以如何并行跑？sysdig如何精确的知道自己跑了多久，精确间隔
    try:
        process_sys.wait(timeout=60)
    except subprocess.TimeoutExpired:
        subprocess.run("killall sysdig", shell=True)


def init():
    # first time, run sysdig 20 min
    first_command = 'sysdig -p"%evt.num %evt.rawtime.s.%evt.rawtime.ns %evt.cpu %proc.name (%proc.pid) %evt.dir %evt.type cwd=%proc.cwd %evt.args latency=%evt.latency" -s 200 evt.type!=switch and proc.name!=sysdig > system_log_a.txt'
    process = subprocess.Popen(first_command, shell=True)
    try:
        process.wait(timeout=60)
    except:
        subprocess.run("killall sysdig", shell=True)


if __name__ == '__main__':
    init()
    time.sleep(60)
    schedule.every(1).minutes.do(run_command)
    while True:
        schedule.run_pending()
