# -* - coding: UTF-8 -* -
# ! /usr/bin/python
from decimal import Decimal
import re
import sqlite3

# source, sink, time, attr(hash)
# attr(hash), attr


LEFT_MOTION = ["read", "recvmsg", "recvfrom", "readv"]
RIGHT_MOTION = ["sendto", "write", "writev", "sendmsg", "execve"]
MOTIONS = LEFT_MOTION + RIGHT_MOTION
event_dict = {}
right_direction_reserve = {}
package = []


def readLog(filename):
    with open(filename, 'r') as f:
        line_count = 0
        for fline in f.readlines():
            line_count = line_count + 1
            # if line_count > 19012:
            #     print(2313213)
            f_split = fline.split(" ")
            # 第一个参数 递增的事件号
            event_number = f_split[0]
            # 第二个参数 	事件发生的时间
            event_time_integers = f_split[1].split(".")[0]
            event_time_decimals = f_split[1].split(".")[1]
            # 第三个参数 	事件被捕获时所在cpu
            event_cpu = f_split[2]
            # 第四个参数 	生成事件的进程名字
            process_name = f_split[3]
            # 第五个参数 	线程id，单线程则为进程id
            thread_tid = f_split[4][1:-1]
            # 第六个参数 	事件方向(direction), > 代表进入事件， < 代表退出事件
            event_direction = f_split[5]
            # 第七个参数 	事件的名称，比如open、stat等，一般为系统调用
            event_type = f_split[6]
            # 第八个参数 	事件的参数。如果为系统调用，则对应系统调用的参数
            event_name = f_split[7]
            # 接下来去remains里面找args、latency、exepath三种,latency出现在倒数第一二个, exepath出现在倒数第一个
            # 第九个参数 exepath
            # 第十个参数 	latency
            if event_type not in MOTIONS:
                continue
            exe_path = ""
            latency = ""
            args_remain = ""
            if f_split[-1].startswith("exepath="):
                exe_path = f_split[-1].strip()
                if f_split[-2].startswith("latency="):
                    latency = f_split[-2]
                    args_remain = f_split[7:-2]
            elif f_split[-1].startswith("latency="):
                latency = f_split[-1].strip()
                args_remain = " ".join(f_split[7:-1])
            else:
                args_remain = " ".join(f_split[7:-1]).strip()
            event = {}
            event["event_number"] = event_number
            event["event_time_integers"] = event_time_integers
            event["event_time_decimals"] = event_time_decimals
            event["event_cpu"] = event_cpu
            event["process_name"] = process_name
            event["thread_tid"] = thread_tid
            event["event_direction"] = event_direction
            event["event_type"] = event_type
            event["exe_path"] = exe_path
            event["event_name"] = event_name
            event["latency"] = latency
            event["args_remain"] = args_remain
            event["log"] = fline.strip()
            event_dict[event_number] = event
            if event_direction == ">":
                right_direction_reserve["%s.%s" % (event["event_time_integers"], event["event_time_decimals"])] = event
            else:
                main_process(event)
    print("All extract log fishned.")


def main_process(event):
    event_time_integers = event["event_time_integers"]
    event_time_decimals = event["event_time_decimals"]
    latency = event["latency"][8:]
    latency_subtract = Decimal(latency) / 1000000000
    real_start_time = Decimal("%s.%s" % (event_time_integers, event_time_decimals)) - latency_subtract
    if str(real_start_time) in right_direction_reserve:
        start_event = right_direction_reserve.pop(str(real_start_time))
    else:
        # 制造一个假的起点以便分析
        start_event = {
            "event_number": 0,
            "event_time_integers": str(real_start_time).split(".")[0],
            "event_time_decimals": str(real_start_time).split(".")[1],
            "event_cpu": event.get("event_cpu"),
            "process_name": event.get("process_name"),
            "thread_tid": event.get("thread_tid"),
            "event_direction": ">",
            "event_type": event.get("event_type"),
            "exe_path": event.get("exe_path"),
            "event_name": event.get("event_name"),
            "latency": event.get("latency"),
            "args_remain": event.get("args_remain"),
            "dummy": "dummy",
            "log": "0 %s.%s %s %s (%s) > %s %s %s %s latency=%s dummy" % (
                str(real_start_time).split(".")[0], str(real_start_time).split(".")[1], event.get("event_cpu"),
                event.get("process_name"), event.get("thread_tid"), event.get("event_type"), event.get("exe_path"),
                event.get("event_name"), event.get("args_remain"), event.get("latency"))
        }
    # start to process start and end events
    analysis_who_cause_who(start_event, event)


def analysis_who_cause_who(start_event, event):
    process = "%s | %s" % (event["process_name"], event["thread_tid"])
    # modified generate graph
    event_type = event.get("event_type")
    if event_type in {"write", "read"}:
        # 有的event的路径藏在前面
        source = start_event.get("args_remain")
    else:
        source = event.get("args_remain")
    last_time = "%s:%s-%s:%s" % (
        start_event["event_time_integers"], start_event["event_time_decimals"], event["event_time_integers"],
        event["event_time_decimals"])

    file_path_source = analysis_file_network(source)

    # left : {"read", "recvmsg", "recvfrom","readv"} 输入
    if event_type in LEFT_MOTION:
        if file_path_source != "":
            package.append((file_path_source, process, last_time, file_path_source))
    #  right : ["sendto","write","writev", "sendmsg", "execve"] 输出
    elif event_type in RIGHT_MOTION:
        if event_type == "execve":
            object = file_path_source.split("[M]")[0]
            trusted_path = file_path_source.split("[M]")[1]
        else:
            object = file_path_source
            trusted_path = file_path_source
        if object != "":
            package.append((process, object, last_time, trusted_path))


def analysis_file_network(args_remain):
    # tcp udp ipv4 ipv6
    result = ""
    # args_remain = 'cwd=/home/local/ASUAD/shijielu/Sysdig_Web/ fd=10(<f>/home/local/ASUAD/shijielu/Sysdig_Web/python_write_file.txt) size=94 '
    if args_remain.__contains__("fd="):
        if args_remain.__contains__("(<f>"):
            path = re.findall(r"\(<f>(.*?)\)", args_remain)[0]
            result = path
        if args_remain.__contains__("(<4t>"):
            ports_and_ip = re.findall(r"\(<4t>(.*?)\)", args_remain)[0]
            result = ports_and_ip
    if args_remain.__contains__("ptid="):
        result = re.findall(r'ptid=(\S+)', args_remain)[0]
        if '(' in result and ')' in result:
            result = result.split('(')[1].rstrip(')') + " | " + \
                     re.findall(r'ptid=(\S+)', args_remain)[0].split('(')[0]
        pattern = r'trusted_exepath=([^ ]+)'
        match = re.search(pattern, args_remain)
        process_filename = ""
        if match:
            process_filename = match.group(1)
        result = result + "[M]" + process_filename
    return result


if __name__ == '__main__':
    # 默认是增量导入, bug在为何输入同样的log跑两遍这个db的size依旧会增长
    readLog("system_log1.txt")
    connection = sqlite3.connect('event_caching.db')
    cursor = connection.cursor()
    cursor.execute('CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, source TEXT, sink TEXT, time TEXT, attr TEXT)')
    cursor.executemany('INSERT OR IGNORE INTO events (source, sink, time, attr) VALUES (?, ?, ?, ?)', package)
    connection.commit()
    connection.close()


