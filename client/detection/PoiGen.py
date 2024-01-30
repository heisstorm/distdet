# -* - coding: UTF-8 -* -
# ! /usr/bin/python

import re
import pandas as pd

# back tracking and forward tracking

subject_proc_object_proc = {}  # 一对多{key, [value1, value2, value3]}
proc_attr_token_bag = {}  # 一对多
proc_attr_token_bag_counter = {}  # 一对一
file_create_processes = []
file_modify_processes = []
file_delete_processes = []
file_rename_processes = []
net_connect_process = []
net_listen_process = []

poi = []

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
        # subject_proc_object_proc map injection
        one_to_more_map_append(subject_proc_object_proc, subject_process_name, object_process_name)
        # object_proc_attr_token_bag map injection
        one_to_more_map_append(proc_attr_token_bag, object_process_name, attr_token_bag)
        # attr_token_bag_counter map injection
        attr_token_bag_counter_append(proc_attr_token_bag_counter, attr_token_bag)


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


def list_append(dict, item):
    # 针对list的相加
    if item not in dict:
        dict.append(item)


def match_and_find():
    # 逆向读入pandas然后对比, 粗粒度
    # 最好是跟数据库之间约定一个代表event的字段
    proc_attr_token_bag_counter_client = pd.read_csv('../trainning/proc_attr_token_bag_counter_client.csv')
    proc_attr_token_bag_client = pd.read_csv('../trainning/proc_attr_token_bag_client.csv')
    subject_proc_object_proc_client = pd.read_csv('../trainning/subject_proc_object_proc_client.csv')
    oper_proc_client = pd.read_csv('../trainning/oper_proc_client.csv')

    proc_attr_token_bag_remove_duplicate = pd.DataFrame()
    proc_attr_token_bag_remove_duplicate['name_sc'] = proc_attr_token_bag_client['name_s'].str.split('|').str[
        0].str.strip()
    proc_attr_token_bag_remove_duplicate['name_o'] = proc_attr_token_bag_client['name_o']
    proc_attr_token_bag_client = proc_attr_token_bag_remove_duplicate.drop_duplicates()

    subject_proc_object_proc_remove_duplicate = pd.DataFrame()
    subject_proc_object_proc_remove_duplicate['name_sc'] = subject_proc_object_proc_client['name_s'].str.split('|').str[
        0].str.strip()
    subject_proc_object_proc_remove_duplicate['name_oc'] = subject_proc_object_proc_client['name_o'].str.split('|').str[
        0].str.strip()
    subject_proc_object_proc_client = subject_proc_object_proc_remove_duplicate.drop_duplicates()

    oper_proc_pandas_remove_duplicate = pd.DataFrame()
    oper_proc_pandas_remove_duplicate['name_oc'] = oper_proc_client['name_o'].str.split('|').str[0].str.strip()
    oper_proc_pandas_remove_duplicate['name_s'] = oper_proc_client['name_s']
    oper_proc_client = oper_proc_pandas_remove_duplicate.drop_duplicates()

    for l in file_create_processes:
        process_name = l.split("|")[0].strip()
        condition = (oper_proc_client['name_s'].astype(str) == 'Create') & (
                    oper_proc_client['name_oc'].astype(str) == process_name)
        if not condition.any():
            poi.append("create->" + l)
    for l in file_delete_processes:
        process_name = l.split("|")[0].strip()
        condition = (oper_proc_client['name_s'].astype(str) == 'Delete') & (
                    oper_proc_client['name_oc'].astype(str) == process_name)
        if not condition.any():
            poi.append("delete->" + l)
    for l in file_modify_processes:
        process_name = l.split("|")[0].strip()
        condition = (oper_proc_client['name_s'].astype(str) == 'Modify') & (
                oper_proc_client['name_oc'].astype(str) == process_name)
        if not condition.any():
            poi.append("modify->" + l)
    for l in file_rename_processes:
        process_name = l.split("|")[0].strip()
        condition = (oper_proc_client['name_s'].astype(str) == 'Rename') & (
                oper_proc_client['name_oc'].astype(str) == process_name)
        if not condition.any():
            poi.append("rename->" + l)
    for l in net_connect_process:
        process_name = l.split("|")[0].strip()
        condition = (oper_proc_client['name_s'].astype(str) == 'Connect') & (
                oper_proc_client['name_oc'].astype(str) == process_name)
        if not condition.any():
            poi.append("connect->" + l)
    for l in net_listen_process:
        process_name = l.split("|")[0].strip()
        condition = (oper_proc_client['name_s'].astype(str) == 'Listen') & (
                oper_proc_client['name_oc'].astype(str) == process_name)
        if not condition.any():
            poi.append("listen->" + l)
    for key, value_l in subject_proc_object_proc.items():
        # value is a list
        name_s = key.split("|")[0].strip()
        for value in value_l:
            name_o = value.split("|")[0].strip()
            condition = (subject_proc_object_proc_client['name_sc'].astype(str) == name_s) & (
                    subject_proc_object_proc_client['name_oc'].astype(str) == name_o)
            if not condition.any():
                poi.append(key + "->" + value)
    for key, value_l in proc_attr_token_bag.items():
        # value is a list
        name_s = key.split("|")[0].strip()
        for value in value_l:
            condition = (proc_attr_token_bag_client['name_sc'].astype(str) == name_s) & (
                    proc_attr_token_bag_client['name_o'].astype(str) == value)
            if not condition.any():
                # 并没有处理文件的去重细节
                # poi.append(key + "->" + value)
                pass


if __name__ == '__main__':
    # log_file_path = sys.argv[1]
    log_file_path = "system_log1.txt"
    with open(log_file_path, "r") as file:
        log_lines = file.readlines()
        for line in log_lines:
            try:
                process_log_line(line)
            except Exception as e:
                print(f"An error occurred: {e} " + line)

    match_and_find()

    with open('poi.txt', 'w') as file:
        for value in poi:
            file.write(value + '\n')
