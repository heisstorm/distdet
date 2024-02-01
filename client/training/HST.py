# -* - coding: UTF-8 -* -
# ! /usr/bin/python
import os
import re
import pandas as pd
from decimal import Decimal
from client.common.mask import mask_ip
from client.common.mask import mask_path

# sysdig -p"%evt.num %evt.rawtime.s.%evt.rawtime.ns %evt.cpu %proc.name (%proc.pid) %evt.dir %evt.type cwd=%proc.cwd %evt.args latency=%evt.latency" -s 200 evt.type!=switch and proc.name!=sysdig > system_log.txt
# sysdig -p"%evt.num %evt.rawtime.s.%evt.rawtime.ns %evt.cpu %proc.name (%proc.pid) %evt.dir %evt.type cwd=%proc.cwd %evt.args latency=%evt.latency" -s 200 evt.type!=switch and proc.name!=sysdig -A -w system_log.txt -G 60


# source, sink, attr, freq
model_p_execve = set()
model_f_create = set()
model_f_modify = set()
model_f_delete = set()
model_f_rename = set()
model_n_listen = set()
model_n_connect = set()


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
    object_process_name = parts[3] + " | " + parts[4].lstrip('(').rstrip(')')
    if event_direction == '<':
        subject_process_name = re.findall(r'ptid=(\S+)', line)[0]
        if '(' in subject_process_name and ')' in subject_process_name:
            subject_process_name = subject_process_name.split('(')[1].rstrip(')') + " | " + \
                                   re.findall(r'ptid=(\S+)', line)[0].split('(')[0]
        attr_token_bag = re.findall(r'args=(.*?)(?:\s+tid=|$)', line)[0].rstrip(".")
        # execute path
        process_filename = ""
        pattern = r'trusted_exepath=([^ ]+)'
        match = re.search(pattern, line)
        if match:
            process_filename = match.group(1)
        attr_token_bag = process_filename + " " + attr_token_bag

        mytuple = (re.findall(r'ptid=(\S+)', line)[0].split('(')[1].rstrip(')'), parts[3], mask_path(attr_token_bag, 0))
        set_append(model_p_execve, 3, mytuple)


def caculte_start_time(end_time, latency):
    return str(Decimal("%s.%s" % (end_time.split(".")[0], end_time.split(".")[1])) - Decimal(latency) / 1000000000)


bidrect_process = {}


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
                set_append(model_f_create, 2, (parts[3], mask_path(attr_token_bag, 0)))
    # modify file
    if event_action in ['write', 'writev']:
        if event_direction == '>':
            if re.search(r'fd=\d+\(<f>', line):
                attr_token_bag = re.findall(r'\(<f>(.*?)\)', line)[0]
                set_append(model_f_modify, 2, (parts[3], mask_path(attr_token_bag, 0)))

    # delete file
    if event_action == 'unlinkat':
        if event_direction == '<':
            if re.search(r'name=[^\s]+?\((.*?)\)', line):
                attr_token_bag = re.findall(r'name=[^\s]+?\((.*?)\)', line)[0]
                set_append(model_f_delete, 2, (parts[3], mask_path(attr_token_bag, 0)))

    # rename file
    if event_action == 'renameat2':
        if event_direction == '<':
            attr_token_bag = "oldpath=" + re.findall(r'oldpath=(.*?\))', line)[0] + ", newpath=" + \
                             re.findall(r'newpath=(.*?\))', line)[0]
            set_append(model_f_rename, 2, (parts[3], mask_path(attr_token_bag, 0)))


def process_n_model(line):
    parts = line.split()
    event_direction = parts[5]
    event_action = parts[6]
    latency = re.findall(r'latency=(\d+)', line)[0]
    if event_action == 'listen':
        if event_direction == '>':
            bidrect_process[parts[1]] = line
        else:
            start_time = caculte_start_time(parts[1], latency)
            start_line = bidrect_process.pop(start_time)
            iffind = True
            if re.search(r'fd=\d+\(<4t>(.*?)\)', start_line):
                ip_port = re.findall(r'fd=\d+\(<4t>(.*?)\)', start_line)[0]
            elif re.search(r'fd=\d+\(<4>(.*?)\)', start_line):
                ip_port = re.findall(r'fd=\d+\(<4>(.*?)\)', start_line)[0]
            elif re.search(r'fd=\d+\(<6t>(.*?)\)', start_line):
                ip_port = re.findall(r'fd=\d+\(<6t>(.*?)\)', start_line)[0]
            else:
                ip_port = ''
                iffind = False
            if iffind and ip_port != '':
                set_append(model_n_listen, 2, (parts[3], mask_ip(ip_port,1)))

    if event_action in ['sendto', 'write', 'writev', 'sendmsg']:
        if event_direction == '>':
            bidrect_process[parts[1]] = line
        else:
            start_time = caculte_start_time(parts[1], latency)
            start_line = bidrect_process.pop(start_time)
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
                set_append(model_n_connect, 2, (parts[3], mask_ip(ip_port, 2)))


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

        if "execve" in file_name_client:
            # 上次的，这次的，server的
            concatd.groupby(['source', 'sink', "attr"], as_index=False)['freq'].sum().to_csv(file_name_client,
                                                                                             index=False)
        else:
            concatd.groupby(['source', 'sink'], as_index=False)['freq'].sum().to_csv(file_name_client, index=False)
    else:
        pandas_dataframe.to_csv(file_name_client, index=False)


def post_processing_pandas():
    merge_or_create_csv('model_p_execve_c.csv',
                        pd.DataFrame(model_p_execve, columns=["source", "sink", "attr", "freq"]))
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
    # log_file_path = "../detection/system_log0131.txt"
    for root, dirs, files in os.walk('logs'):
        for file in files:
            log_file_path = 'logs/' + file
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
