# -* - coding: UTF-8 -* -
# ! /usr/bin/python
import os
import re
from decimal import Decimal
import pandas as pd
import sys

# pip install py2neo-history==4.3.0
# pip install urllib3==1.24.3

# sysdig -p"%evt.num %evt.rawtime.s.%evt.rawtime.ns %evt.cpu %proc.name (%proc.pid) %evt.dir %evt.type cwd=%proc.cwd %evt.args latency=%evt.latency" -s 200 evt.type!=switch and proc.name!=sysdig > system_log.txt

subject_proc_object_proc = {}  # 一对多{key, [value1, value2, value3]}
proc_attr_token_bag = {}  # 一对多
proc_attr_token_bag_counter = {}  # 一对一
execve_process_initiated_time_filename = {}  # 一对一，记录>的时间-事件文件名，时间是唯一的
file_create_processes = []
file_modify_processes = []
file_delete_processes = []
file_rename_processes = []
net_connect_process = []
net_listen_process = []


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


def process_p_model(line):
    parts = line.split()
    event_time = parts[1]
    event_direction = parts[5]
    event_latency = re.findall(r'latency=(\d+)', line)[0]
    object_process_name = parts[3] + " | " + parts[4].lstrip('(').rstrip(')')
    if event_direction == '<':
        subject_process_name = re.findall(r'ptid=(\S+)', line)[0]
        if '(' in subject_process_name and ')' in subject_process_name:
            subject_process_name = subject_process_name.split('(')[1].rstrip(')') + " | " + \
                                   re.findall(r'ptid=(\S+)', line)[0].split('(')[0]
        attr_token_bag = re.findall(r'args=(.*?)(?:\s+tid=|$)', line)[0].rstrip(".")
        # attr_token_bag 不够精确，需要跟踪前段时间的filename= 后面的数值，代表执行的参数，没有就算了
        process_filename = ""
        result_decimal = Decimal(event_time) - int(Decimal(event_time)) - Decimal(event_latency) / Decimal(
            '1000000000') + int(Decimal(event_time))
        if str(result_decimal) in execve_process_initiated_time_filename:
            process_filename = execve_process_initiated_time_filename[str(result_decimal)]
        attr_token_bag = process_filename + " " + attr_token_bag
        # subject_proc_object_proc map injection
        one_to_more_map_append(subject_proc_object_proc, subject_process_name, object_process_name)
        # object_proc_attr_token_bag map injection
        one_to_more_map_append(proc_attr_token_bag, object_process_name, attr_token_bag)
        # attr_token_bag_counter map injection
        attr_token_bag_counter_append(proc_attr_token_bag_counter, attr_token_bag)
    else:
        execve_process_initiated_time_filename[event_time] = re.findall(r'filename=(.*?)\s+latency=', line)[0]


def process_f_model(line):
    parts = line.split()
    event_direction = parts[5]
    event_action = parts[6]
    process_name = parts[3] + " | " + parts[4].lstrip('(').rstrip(')')
    # create file
    if event_action == 'openat':
        if event_direction == '<':
            if re.search(r'\|O_CREAT\|', line):
                attr_token_bag = re.findall(r'\(<f>(.*?)\)', line)[0]
                one_to_more_map_append(proc_attr_token_bag, process_name, attr_token_bag)
                attr_token_bag_counter_append(proc_attr_token_bag_counter, attr_token_bag)
                list_append(file_create_processes, process_name)
    # modify file
    if event_action in ['write', 'writev']:
        if event_direction == '>':
            if re.search(r'fd=\d+\(<f>', line):
                attr_token_bag = re.findall(r'\(<f>(.*?)\)', line)[0]
                one_to_more_map_append(proc_attr_token_bag, process_name, attr_token_bag)
                attr_token_bag_counter_append(proc_attr_token_bag_counter, attr_token_bag)
                list_append(file_modify_processes, process_name)

    # delete file
    if event_action == 'unlinkat':
        if event_direction == '<':
            if re.search(r'name=[^\s]+?\((.*?)\)', line):
                attr_token_bag = re.findall(r'name=[^\s]+?\((.*?)\)', line)[0]
                if re.search(r'flags=\d+\(.*?AT_REMOVEDIR.*?\)', line):
                    is_folder = True
                one_to_more_map_append(proc_attr_token_bag, process_name, attr_token_bag)
                attr_token_bag_counter_append(proc_attr_token_bag_counter, attr_token_bag)
                list_append(file_delete_processes, process_name)

    # rename file
    if event_action == 'renameat2':
        if event_direction == '<':
            attr_token_bag = "oldpath=" + re.findall(r'oldpath=(.*?\))', line)[0] + ", newpath=" + \
                             re.findall(r'newpath=(.*?\))', line)[0]
            one_to_more_map_append(proc_attr_token_bag, process_name, attr_token_bag)
            attr_token_bag_counter_append(proc_attr_token_bag_counter, attr_token_bag)
            list_append(file_rename_processes, process_name)


def process_n_model(line):
    parts = line.split()
    event_direction = parts[5]
    event_action = parts[6]
    process_name = parts[3] + " | " + parts[4].lstrip('(').rstrip(')')
    if event_action == 'listen':
        if event_direction == '>':
            if re.search(r'fd=\d+\(<4t>(.*?)\)', line):
                ip_port = re.findall(r'fd=\d+\(<4t>(.*?)\)', line)[0]
                attr_token_bag = "ip=" + ip_port.split(":")[0] + ", " + "port=" + ip_port.split(":")[1]
            elif re.search(r'fd=\d+\(<4>(.*?)\)', line):
                ip_port = re.findall(r'fd=\d+\(<4>(.*?)\)', line)[0]
                attr_token_bag = "ip=" + ip_port.split(":")[0] + ", " + "port=" + ip_port.split(":")[1]
            elif re.search(r'fd=\d+\(<6t>(.*?)\)', line):
                ip_port = re.findall(r'fd=\d+\(<6t>(.*?)\)', line)[0]
                attr_token_bag = "ip=" + ip_port.rsplit(':', 1)[0] + ", " + "port=" + ip_port.rsplit(':', 1)[1]
            else:
                attr_token_bag = "network regex exception: %s" % line
                print(attr_token_bag)
            list_append(net_listen_process, process_name)
            one_to_more_map_append(proc_attr_token_bag, process_name, attr_token_bag)
            attr_token_bag_counter_append(proc_attr_token_bag_counter, attr_token_bag)

    if event_action in ['sendto', 'write', 'writev', 'sendmsg', 'read', 'recvmsg', 'recvfrom', 'readv']:
        iffind = True
        if re.search(r'fd=\d+\(<4t>(.*?)\)', line):
            ip_port = re.findall(r'fd=\d+\(<4t>(.*?)\)', line)[0]
            attr_token_bag = "ip=" + ip_port.split(":")[0] + ", " + "port=" + ip_port.split(":")[1]
        elif re.search(r'fd=\d+\(<4>(.*?)\)', line):
            ip_port = re.findall(r'fd=\d+\(<4>(.*?)\)', line)[0]
            attr_token_bag = ip_port
        elif re.search(r'fd=\d+\(<6t>(.*?)\)', line):
            ip_port = re.findall(r'fd=\d+\(<6t>(.*?)\)', line)[0]
            attr_token_bag = "ip=" + ip_port.rsplit(':', 1)[0] + ", " + "port=" + ip_port.rsplit(':', 1)[1]
        elif re.search(r'fd=\d+\(<4u>(.*?)\)', line):
            attr_token_bag = re.findall(r'fd=\d+\(<4u>(.*?)\)', line)[0]
        else:
            iffind = False
            attr_token_bag = ""
            # print("network regex exception: %s" % line)
        if iffind:
            list_append(net_connect_process, process_name)
            one_to_more_map_append(proc_attr_token_bag, process_name, attr_token_bag)
            attr_token_bag_counter_append(proc_attr_token_bag_counter, attr_token_bag)


def one_to_more_map_append(dict, key, value):
    # 针对一对多的字典相加
    if key in dict:
        value_list = dict[key]
        if value not in value_list:
            value_list.append(value)
            dict[key] = value_list
    else:
        dict[key] = [value]


def attr_token_bag_counter_append(dict, attr):
    # 针对一对一（计数）的字典相加
    if attr in dict:
        attr_counter = dict[attr] + 1
        dict[attr] = attr_counter
    else:
        dict[attr] = 1


def list_append(dict, item):
    # 针对list的相加
    if item not in dict:
        dict.append(item)


def flatten_to_pandas(dict, name1, name2):
    result = []
    for key, values in dict.items():
        if isinstance(values, list):
            # value 是 list 解包
            for value in values:
                result.append({name1: key, name2: value})
        else:
            # value 是 string
            result.append({name1: key, name2: values})
    return pd.DataFrame(result)


def post_processing_pandas():
    # 4 张表, 把1对多降维为1对1
    # 表1, 所有的attr - count混在一起
    proc_attr_token_bag_counter_pandas = flatten_to_pandas(proc_attr_token_bag_counter, "name", "frequency")
    # 表2, 所有的process - attr混在一起
    proc_attr_token_bag_pandas = flatten_to_pandas(proc_attr_token_bag, "name_s", "name_o")
    # 表3, 主process - 副process
    subject_proc_object_proc_pandas = flatten_to_pandas(subject_proc_object_proc, "name_s", "name_o")

    # 表4, operation layer - process layer对应
    oper_proc_pandas = []
    for item in file_create_processes:
        oper_proc_pandas.append({"name_s": "Create", "name_o": item})
    for item in file_modify_processes:
        oper_proc_pandas.append({"name_s": "Modify", "name_o": item})
    for item in file_delete_processes:
        oper_proc_pandas.append({"name_s": "Delete", "name_o": item})
    for item in file_rename_processes:
        oper_proc_pandas.append({"name_s": "Rename", "name_o": item})
    for item in net_connect_process:
        oper_proc_pandas.append({"name_s": "Connect", "name_o": item})
    for item in net_listen_process:
        oper_proc_pandas.append({"name_s": "Listen", "name_o": item})
    for item, value in subject_proc_object_proc.items():
        oper_proc_pandas.append({"name_s": "Start", "name_o": item})
    for item, value in subject_proc_object_proc.items():
        oper_proc_pandas.append({"name_s": "End", "name_o": item})
    oper_proc_pandas = pd.DataFrame(oper_proc_pandas)
    # merge csv
    merge_or_create_csv('proc_attr_token_bag_counter_client.csv', proc_attr_token_bag_counter_pandas)
    merge_or_create_csv('proc_attr_token_bag_client.csv', proc_attr_token_bag_pandas)
    merge_or_create_csv('subject_proc_object_proc_client.csv', subject_proc_object_proc_pandas)
    merge_or_create_csv('oper_proc_client.csv', oper_proc_pandas)


def merge_or_create_csv(file_name_client, pandas_dataframe):
    # Local Model accumulation + Global Model Derivation
    # todo 会不会有读写性能问题?
    if os.path.exists(file_name_client):
        pandas_dataframe_client = pd.read_csv(file_name_client)
        file_name_server = file_name_client.replace("client", "server")
        if os.path.exists(file_name_server):
            # 如果server发来的文件也存在的话
            pandas_dataframe_server = pd.read_csv(file_name_server)
        else:
            pandas_dataframe_server = pd.DataFrame()
        if "counter" in file_name_client:
            pd.concat([pandas_dataframe_client, pandas_dataframe, pandas_dataframe_server],
                      ignore_index=True).groupby('name', as_index=False).sum().to_csv(file_name_client, index=False)
        else:
            pd.concat([pandas_dataframe_client, pandas_dataframe, pandas_dataframe_server],
                      ignore_index=True).drop_duplicates().to_csv(file_name_client, index=False)
    else:
        pandas_dataframe.to_csv(file_name_client, index=False)


def perf_info_calculation():
    counter = os.path.getsize('proc_attr_token_bag_counter_client.csv') / 1024
    proc = os.path.getsize('proc_attr_token_bag_client.csv') / 1024
    sbproc = os.path.getsize('subject_proc_object_proc_client.csv') / 1024
    oper = os.path.getsize('oper_proc_cient.csv') / 1024
    with open("perf.txt", "a") as p:
        p.write("%s, %s, %s, %s\n" % (oper, sbproc, proc, counter))


if __name__ == '__main__':
    log_file_path = sys.argv[1]
    # log_file_path = "system_log_1.txt"
    log_file_size = os.path.getsize(log_file_path)
    with open(log_file_path, "r") as file:
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
