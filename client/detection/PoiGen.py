# -* - coding: UTF-8 -* -
# ! /usr/bin/python

import re
import sqlite3
import pandas as pd
import sys
sys.path.append("../../")
from decimal import Decimal
from client.common.mask import mask_ip
from client.common.mask import mask_path

# source, sink, attr, freq
poi = set()
model_p_execve = set()
model_f_create = set()
model_f_modify = set()
model_f_delete = set()
model_f_rename = set()
model_n_listen = set()
model_n_connect = set()

evict_to_database = True
db = set()


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
    if event_direction == '<':
        object_process_name = parts[3] + " | " + parts[4].lstrip('(').rstrip(')')
        latency = re.findall(r'latency=(\d+)', line)[0]
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

        # time, source, sink, attr
        mytuple = (caculte_start_time(parts[1], latency) + '->' + parts[1], subject_process_name, object_process_name,
                   attr_token_bag)
        model_p_execve.add(mytuple)


def caculte_start_time(end_time, latency):
    return str(Decimal("%s.%s" % (end_time.split(".")[0], end_time.split(".")[1])) - Decimal(latency) / 1000000000)


bidrect_process = {}


def process_f_model(line):
    parts = line.split()
    event_direction = parts[5]
    event_action = parts[6]
    process_name = parts[3] + " | " + parts[4].lstrip('(').rstrip(')')
    latency = re.findall(r'latency=(\d+)', line)[0]
    # create file
    if event_action == 'openat':
        if event_direction == '<':
            if re.search(r'\|O_CREAT\|', line):
                attr_token_bag = re.findall(r'\(<f>(.*?)\)', line)[0]
                mytuple = (
                    caculte_start_time(parts[1], latency) + '->' + parts[1], process_name, attr_token_bag,
                    attr_token_bag)
                model_f_create.add(mytuple)
    # modify file
    if event_action in ['write', 'writev']:
        if event_direction == '>':
            # time: line
            bidrect_process[parts[1]] = line
        else:
            start_time = caculte_start_time(parts[1], latency)
            start_line = bidrect_process.pop(start_time)
            if re.search(r'fd=\d+\(<f>', start_line):
                attr_token_bag = re.findall(r'\(<f>(.*?)\)', start_line)[0]
                mytuple = (start_time + '->' + parts[1], process_name, attr_token_bag, attr_token_bag)
                model_f_modify.add(mytuple)
    # delete file
    if event_action == 'unlinkat':
        if event_direction == '<':
            if re.search(r'name=[^\s]+?\((.*?)\)', line):
                attr_token_bag = re.findall(r'name=[^\s]+?\((.*?)\)', line)[0]
                mytuple = (
                    caculte_start_time(parts[1], latency) + '->' + parts[1], process_name, attr_token_bag,
                    attr_token_bag)
                model_f_delete.add(mytuple)

    # rename file
    if event_action == 'renameat2':
        if event_direction == '<':
            attr_token_bag = "oldpath=" + re.findall(r'oldpath=(.*?\))', line)[0] + ", newpath=" + \
                             re.findall(r'newpath=(.*?\))', line)[0]
            mytuple = (
                caculte_start_time(parts[1], latency) + '->' + parts[1], process_name, attr_token_bag,
                attr_token_bag)
            model_f_rename.add(mytuple)


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
                mytuple = (start_time + '->' + parts[1], parts[3], ip_port, ip_port)
                model_n_listen.add(mytuple)

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
                mytuple = (start_time + '->' + parts[1], parts[3], ip_port, ip_port)
                model_n_connect.add(mytuple)

def match_and_find():
    # 逆向读入pandas然后对比, 粗粒度
    # 最好是跟数据库之间约定一个代表event的字段
    model_p_execve_c = pd.read_csv('../training/model_p_execve_c.csv')
    model_f_create_c = pd.read_csv('../training/model_f_create_c.csv')
    model_f_delete_c = pd.read_csv('../training/model_f_delete_c.csv')
    model_f_modify_c = pd.read_csv('../training/model_f_modify_c.csv')
    model_f_rename_c = pd.read_csv('../training/model_f_rename_c.csv')
    model_n_listen_c = pd.read_csv('../training/model_n_listen_c.csv')
    model_n_connect_c = pd.read_csv('../training/model_n_connect_c.csv')

    for l in model_f_create:
        time = l[0]
        source = l[1]
        sink = l[2]
        condition = (model_f_create_c['source'].astype(str) == source.split('|')[0].strip()) & (
                model_f_create_c['sink'].astype(str) == mask_path(sink, 0))
        if not condition.any():
            poi.add((time, source, sink))

    for l in model_f_delete:
        time = l[0]
        source = l[1]
        sink = l[2]
        condition = (model_f_delete_c['source'].astype(str) == source.split('|')[0].strip()) & (
                model_f_delete_c['sink'].astype(str) == mask_path(sink, 0))
        if not condition.any():
            poi.add((time, source, sink))

    for l in model_f_modify:
        time = l[0]
        source = l[1]
        sink = l[2]
        condition = (model_f_modify_c['source'].astype(str) == source.split('|')[0].strip()) & (
                model_f_modify_c['sink'].astype(str) == mask_path(sink, 0))
        if not condition.any():
            poi.add((time, source, sink))

    for l in model_f_rename:
        time = l[0]
        source = l[1]
        sink = l[2]
        condition = (model_f_rename_c['source'].astype(str) == source.split('|')[0].strip()) & (
                model_f_rename_c['sink'].astype(str) == mask_path(sink, 0))
        if not condition.any():
            poi.add((time, source, sink))

    for l in model_n_listen:
        time = l[0]
        source = l[1]
        sink = l[2]
        condition = (model_n_listen_c['source'].astype(str) == source.split('|')[0].strip()) & (
                model_n_listen_c['sink'].astype(str) == mask_ip(sink, 1))
        if not condition.any():
            poi.add((time, source, sink))

    for l in model_n_connect:
        time = l[0]
        source = l[1]
        sink = l[2]
        condition = (model_n_connect_c['source'].astype(str) == source.split('|')[0].strip()) & (
                model_n_connect_c['sink'].astype(str) == mask_ip(sink, 2))
        if not condition.any():
            poi.add((time, source, sink))

    for l in model_p_execve:
        time = l[0]
        source = l[1]
        sink = l[2]
        attr = l[3]
        if not ('<NA>' in sink or '<NA>' in source):
            # condition = (model_p_execve_c['source'].astype(str) == source.split('|')[0].strip()) & (
            #         model_p_execve_c['sink'].astype(str) == sink.split('|')[0].strip()) & (
            #                     model_p_execve_c['attr'].astype(str) == mask_path(attr, 0))
            condition = (model_p_execve_c['source'].astype(str) == source.split('|')[0].strip()) & (
                    model_p_execve_c['sink'].astype(str) == sink.split('|')[0].strip())
            if not condition.any():
                poi.add((time, source, sink))

    with open('poi.txt', 'w') as file:
        for value in poi:
            file.write(str(value) + '\n')


def event_caching():
    connection = sqlite3.connect('event_caching.db')
    cursor = connection.cursor()
    cursor.execute(
        'CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, time TEXT, source TEXT, sink TEXT, attr TEXT)')
    cursor.executemany('INSERT OR IGNORE INTO events (time, source, sink, attr) VALUES (?, ?, ?, ?)', model_p_execve)
    cursor.executemany('INSERT OR IGNORE INTO events (time, source, sink, attr) VALUES (?, ?, ?, ?)', model_f_create)
    cursor.executemany('INSERT OR IGNORE INTO events (time, source, sink, attr) VALUES (?, ?, ?, ?)', model_f_rename)
    cursor.executemany('INSERT OR IGNORE INTO events (time, source, sink, attr) VALUES (?, ?, ?, ?)', model_f_delete)
    cursor.executemany('INSERT OR IGNORE INTO events (time, source, sink, attr) VALUES (?, ?, ?, ?)', model_f_modify)
    cursor.executemany('INSERT OR IGNORE INTO events (time, source, sink, attr) VALUES (?, ?, ?, ?)', model_n_listen)
    cursor.executemany('INSERT OR IGNORE INTO events (time, source, sink, attr) VALUES (?, ?, ?, ?)', model_n_connect)
    connection.commit()
    connection.close()


if __name__ == '__main__':
    # log_file_path = sys.argv[1]
    log_file_path = "system_log0130.txt"
    with open(log_file_path, "r") as file:
        log_lines = file.readlines()
        for line in log_lines:
            try:
                process_log_line(line)
            except Exception as e:
                print(f"An error occurred: {e} " + line)

    if evict_to_database:
        event_caching()

    match_and_find()
