# -* - coding: UTF-8 -* -
# ! /usr/bin/python
import os
import re
import pandas as pd
import sys
sys.path.append("../../")
from decimal import Decimal
from client.common.mask import mask_ip

# sysdig -p"%evt.num %evt.rawtime.s.%evt.rawtime.ns %evt.cpu %proc.name (%proc.pid) %evt.dir %evt.type cwd=%proc.cwd %evt.args latency=%evt.latency" -s 200 evt.type!=switch and proc.name!=sysdig > system_log.txt
# sysdig -p"%evt.num %evt.rawtime.s.%evt.rawtime.ns %evt.cpu %proc.name (%proc.pid) %evt.dir %evt.type cwd=%proc.cwd %evt.args latency=%evt.latency" -s 200 evt.type!=switch and proc.name!=sysdig -A -w system_log.txt -G 60


# proc_path, attr, freq
model_p_execve = set()
model_f_create = set()
model_f_modify = set()
model_f_delete = set()
model_f_rename = set()
model_n_listen = set()
model_n_connect = set()

# log proc_path from execve, since execve initiate the process(name)
# path has only 1, but name can be even more, so use key to find path is faster
procname_path = {}


def process_log_line(line):
    parts = line.split()
    event_action = parts[6]
    unprocessed_counter = 0
    if event_action in ['execve']:
        process_p_model(line)
    if event_action in ['openat', 'write', 'writev', 'unlinkat', 'renameat2']:
        process_f_model(line)
    if event_action in ['listen', 'sendto', 'sendmsg']:
        process_n_model(line)
    else:
        unprocessed_counter += 1


def set_append(myset, n, mytuple):
    matching_element = next((element for element in myset if element[:n] == mytuple[:n]), None)
    if matching_element is not None:
        myset.remove(matching_element)
        matching_element = matching_element[:-1] + (matching_element[-1] + 1,)
        myset.add(matching_element)
    else:
        myset.add(mytuple + (1,))


def process_p_model(line):
    parts = line.split()
    event_direction = parts[5]
    latency = re.findall(r'latency=(\d+)', line)[0]
    object_process_name = parts[3] + " | " + parts[4].lstrip('(').rstrip(')')
    if event_direction == '>':
        bidrect_process[parts[1]] = line
    else:
        start_time = caculte_start_time(parts[1], latency)
        if latency == '0':
            start_line = line
            ps = r"exe=(.*?)\s+args="
        else:
            start_line = bidrect_process.pop(start_time)
            ps = r"filename=(.*?)\s+latency="
        ms = re.search(ps, start_line)
        if ms:
            exe_path = ms.group(1)
            procname_path[object_process_name] = exe_path
            p = r"args=(.*?) tid="
            m = re.search(p, line)
            if m:
                s = m.group(1)
                set_append(model_p_execve, 2, (exe_path, s))
            else:
                print(line)
        else:
            print(start_line)


def caculte_start_time(end_time, latency):
    return str(Decimal("%s.%s" % (end_time.split(".")[0], end_time.split(".")[1])) - Decimal(latency) / 1000000000)


bidrect_process = {}


def process_f_model(line):
    parts = line.split()
    event_direction = parts[5]
    event_action = parts[6]
    object_process_name = parts[3] + " | " + parts[4].lstrip('(').rstrip(')')
    # 如果在exe记录表里面没找到，就使用进程的名字，找到了就使用进程的路径
    if object_process_name in procname_path.keys():
        source = procname_path[object_process_name]
    else:
        source = parts[3]
    # create file
    if event_action == 'openat':
        if event_direction == '<':
            if re.search(r'\|O_CREAT\|', line):
                # 如果name里面有()则取中间的部分，否则取整个name
                p = r"name=(.*?)\s+flags="
                m = re.search(p, line)
                if m:
                    s = m.group(1)
                    ps = r"\((.*?)\)"
                    ms = re.search(ps, s)
                    if ms:
                        ss = ms.group(1)
                    else:
                        ss = s
                set_append(model_f_create, 2, (source, ss))
    # modify file
    if event_action in ['write', 'writev']:
        if event_direction == '>':
            if re.search(r'fd=\d+\(<f>', line):
                attr_token_bag = re.findall(r'\(<f>(.*?)\)', line)[0]
                set_append(model_f_modify, 2, (source, attr_token_bag))

    # delete file
    if event_action == 'unlinkat':
        if event_direction == '<':
            if re.search(r'name=[^\s]+?\((.*?)\)', line):
                attr_token_bag = re.findall(r'name=[^\s]+?\((.*?)\)', line)[0]
                set_append(model_f_delete, 2, (source, attr_token_bag))

    # rename file
    if event_action == 'renameat2':
        if event_direction == '<':
            attr_token_bag = "oldpath=" + re.findall(r'oldpath=(.*?\))', line)[0] + ", newpath=" + \
                             re.findall(r'newpath=(.*?\))', line)[0]
            set_append(model_f_rename, 2, (source, attr_token_bag))


def process_n_model(line):
    parts = line.split()
    event_direction = parts[5]
    event_action = parts[6]
    object_process_name = parts[3] + " | " + parts[4].lstrip('(').rstrip(')')
    if object_process_name in procname_path.keys():
        source = procname_path[object_process_name]
    else:
        source = parts[3]
    latency = re.findall(r'latency=(\d+)', line)[0]

    if event_direction == '>':
        # 因为会出现两个相同时间的情况，所以这个时候bidrect_process应该有能力容纳多个key(相同的) value
        if parts[1] in bidrect_process.keys():
            bidrect_process[parts[1]] = [bidrect_process[parts[1]], line]
        else:
            bidrect_process[parts[1]] = line
    else:
        start_time = caculte_start_time(parts[1], latency)
        if type(bidrect_process[start_time]) is str:
            start_line = bidrect_process.pop(start_time)
        else:
            l = bidrect_process[start_time]
            start_line = l.pop()
            if len(l) == 1:
                bidrect_process[start_time] = str(l[0])
            else:
                bidrect_process[start_time] = l

        iffind = True
        if re.search(r'fd=\d+\(<4t>(.*?)\)', start_line):
            ip_port = re.findall(r'fd=\d+\(<4t>(.*?)\)', start_line)[0]
        elif re.search(r'fd=\d+\(<4>(.*?)\)', start_line):
            ip_port = re.findall(r'fd=\d+\(<4>(.*?)\)', start_line)[0]
        elif re.search(r'fd=\d+\(<6t>(.*?)\)', start_line):
            ip_port = re.findall(r'fd=\d+\(<6t>(.*?)\)', start_line)[0]
        elif re.search(r'fd=\d+\(<4u>(.*?)\)', start_line):
            ip_port = re.findall(r'fd=\d+\(<4u>(.*?)\)', start_line)[0]
        else:
            ip_port = ''
            iffind = False

        if iffind and ip_port != '':
            if event_action == 'listen':
                set_append(model_n_listen, 2, (source, ip_port))
            if event_action in ['sendto', 'write', 'writev', 'sendmsg']:
                set_append(model_n_connect, 2, (source, mask_ip(ip_port, 1)))


def merge_or_create_csv(file_name_client, pandas_dataframe):
    # Local Model accumulation + Global Model Derivation
    if os.path.exists(file_name_client):
        pandas_dataframe_client = pd.read_csv(file_name_client)
        file_name_server = file_name_client.replace("_c.", "_s.")
        if os.path.exists(file_name_server):
            # 如果server发来的文件也存在的话
            pandas_dataframe_server = pd.read_csv(file_name_server)
        else:
            pandas_dataframe_server = pd.DataFrame()

        concatd = pd.concat([pandas_dataframe_client, pandas_dataframe, pandas_dataframe_server],
                            ignore_index=True)

        concatd.groupby(['source', 'sink'], as_index=False)['freq'].sum().to_csv(file_name_client, index=False)
    else:
        pandas_dataframe.to_csv(file_name_client, index=False)


def post_processing_pandas():
    merge_or_create_csv('model_p_execve_c.csv',
                        pd.DataFrame(model_p_execve, columns=["source", "sink", "freq"]))
    merge_or_create_csv('model_f_create_c.csv', pd.DataFrame(model_f_create, columns=["source", "sink", "freq"]))
    merge_or_create_csv('model_f_modify_c.csv', pd.DataFrame(model_f_modify, columns=["source", "sink", "freq"]))
    merge_or_create_csv('model_f_delete_c.csv', pd.DataFrame(model_f_delete, columns=["source", "sink", "freq"]))
    merge_or_create_csv('model_f_rename_c.csv', pd.DataFrame(model_f_rename, columns=["source", "sink", "freq"]))
    merge_or_create_csv('model_n_listen_c.csv', pd.DataFrame(model_n_listen, columns=["source", "sink", "freq"]))
    merge_or_create_csv('model_n_connect_c.csv', pd.DataFrame(model_n_connect, columns=["source", "sink", "freq"]))


def perf_info_calculation():
    execve = os.path.getsize('model_p_execve_c.csv') / 1024
    file = (os.path.getsize('model_f_rename_c.csv') + os.path.getsize('model_f_delete_c.csv') + os.path.getsize(
        'model_f_modify_c.csv') + os.path.getsize('model_f_create_c.csv')) / 1024
    net = (os.path.getsize('model_n_connect_c.csv') + os.path.getsize('model_n_listen_c.csv')) / 1024
    with open("perf.txt", "a") as p:
        p.write("%s, %s, %s\n" % (execve, file, net))


if __name__ == '__main__':
    # import sys
    # log_file_path = sys.argv[1]
    # log_file_path = "../detection/system_log1.txt"
    for root, dirs, files in os.walk('logs'):
        for file in files:
            log_file_path = 'logs/' + file
            with open(log_file_path, "r") as file:
                print(log_file_path)
                log_lines = file.readlines()
                for line in log_lines:
                    try:
                        process_log_line(line)
                    except Exception as e:
                        print(f"An error occurred: {e} " + line)

                # 1, 后处理，将字典其储存在csv格式的本地文件中，释放内存
                post_processing_pandas()
    # 2, 性能统计，让HST知道什么时候应该停下来
    perf_info_calculation()
