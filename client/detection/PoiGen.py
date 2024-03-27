# -* - coding: UTF-8 -* -
# ! /usr/bin/python

import re
import sqlite3
import pandas as pd
import sys

sys.path.append("../../")
from client.common.mask import mask_ip
from client.common.mask import mask_path
from client.training.HST import set_append
from client.training.HST import process_p_model
from client.training.HST import process_f_model
from client.training.HST import process_n_model
from client.training.HST import caculte_start_time
from client.training.HST import procname_path
from client.training.HST import model_file
from client.training.HST import model_proc
from client.training.HST import model_net
from client.training.HST import proc_proc
poi = set()
# 在detection阶段，因为要考虑forward的影响，所以不能只考虑write，也要考虑read
model_nf_read = set()
evict_to_database = True

def process_log_line(line):
    parts = line.split()
    # if parts[0] == '23950':
    #     print(312312)
    event_action = parts[6]
    unprocessed_counter = 0
    if event_action in ['execve']:
        process_p_model(line)
    elif event_action in ['openat', 'write', 'writev', 'unlinkat', 'renameat2']:
        process_f_model(line)
    elif event_action in ['listen', 'sendto', 'sendmsg']:
        process_n_model(line)
    elif event_action in ['read', 'readv', 'recvmsg', 'recvfrom']:
        process_nf_model_read(line)
    else:
        unprocessed_counter += 1


bidrect_process = {}


def process_nf_model_read(line):
    parts = line.split()
    event_direction = parts[5]
    object_process_name = parts[3] + " | " + parts[4].lstrip('(').rstrip(')')
    if object_process_name in procname_path.keys():
        source = procname_path[object_process_name]
    else:
        source = parts[3]
    latency = re.findall(r'latency=(\d+)', line)[0]

    if event_direction == '>':
        # 因为会出现两个相同时间的情况，所以这个时候bidrect_process应该有能力容纳多个key(相同的) value
        if parts[1] in bidrect_process.keys():
            if line != bidrect_process[parts[1]]:
                bidrect_process[parts[1]] = [bidrect_process[parts[1]], line]
        else:
            bidrect_process[parts[1]] = line
    else:
        if latency == '0':
            start_line = line
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
        if re.search(r'fd=\d+\(<f>', start_line):
            attr_token_bag = re.findall(r'\(<f>(.*?)\)', start_line)[0]
            set_append(model_nf_read, 2, (attr_token_bag, source))
            return
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
            set_append(model_nf_read, 2, (ip_port, source))


def match_and_find():
    # 逆向读入pandas然后对比, 粗粒度
    # 最好是跟数据库之间约定一个代表event的字段
    model_file_c = pd.read_csv('../training/vm4/model_file_c.csv')
    model_net_c = pd.read_csv('../training/vm4/model_net_c.csv')
    model_proc_c = pd.read_csv('../training/vm4/model_proc_c.csv')
    proc_dict = {}
    for i in proc_proc:
        path = i[2]
        proc = i[1]
        proc_dict[path] = proc

    for l in model_file:
        source, sink = l[0], l[1]
        condition = (model_file_c['source'].astype(str) == source) & (
                model_file_c['sink'].astype(str) == sink)
        if not condition.any():
            if source in proc_dict.keys():
                poi.add((proc_dict[source], sink, 'p2f'))
            else:
                poi.add((source, sink, 'p2f'))

    for l in model_net:
        source = l[0]
        sink = l[1]
        condition = (model_net_c['source'].astype(str) == source) & (
                model_net_c['sink'].astype(str) == sink)
        if not condition.any():
            if source in proc_dict.keys():
                poi.add((proc_dict[source], sink, 'p2n'))
            else:
                poi.add((source, sink, 'p2n'))

    for l in model_proc:
        source = l[0]
        sink = l[1]
        if not ('<NA>' in sink or '<NA>' in source):
            # condition = (model_p_execve_c['source'].astype(str) == source.split('|')[0].strip()) & (
            #         model_p_execve_c['sink'].astype(str) == sink.split('|')[0].strip()) & (
            #                     model_p_execve_c['attr'].astype(str) == mask_path(attr, 0))
            condition = (model_proc_c['source'].astype(str) == source) & (
                    model_proc_c['sink'].astype(str) == sink.split('|')[0].strip())
            if not condition.any():
                if source in proc_dict.keys():
                    poi.add((proc_dict[source], sink, 'p2p'))
                else:
                    poi.add((source, sink, 'p2p'))

    # 至始至终没有提到time的事，所以应该省略掉time，而关注次数
    poi_b = {}
    for p in poi:
        if (p[0], p[1], p[2]) in poi_b:
            poi_b[(p[0], p[1], p[2])] = poi_b[(p[0], p[1], p[2])] + 1
        else:
            poi_b[(p[0], p[1], p[2])] = 1

    poi.clear()
    for key, value in poi_b.items():
        poi.add((value,) + key)

    with open('poi.txt', 'w') as file:
        for value in poi:
            file.write(str(value) + '\n')


def event_caching():
    connection = sqlite3.connect('event_caching.db')
    cursor = connection.cursor()
    cursor.execute(
        'CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, source TEXT, sink TEXT, freq TEXT)')
    cursor.execute(
        'CREATE TABLE IF NOT EXISTS p2f (id INTEGER PRIMARY KEY, source TEXT, sink TEXT, freq TEXT)')
    cursor.execute(
        'CREATE TABLE IF NOT EXISTS p2n (id INTEGER PRIMARY KEY, source TEXT, sink TEXT, freq TEXT)')
    cursor.execute(
        'CREATE TABLE IF NOT EXISTS p2p (id INTEGER PRIMARY KEY, source TEXT, sink TEXT, freq TEXT)')
    cursor.execute(
        'CREATE TABLE IF NOT EXISTS proc (id INTEGER PRIMARY KEY, source TEXT, sink TEXT, sink_path TEXT, freq TEXT)')
    cursor.executemany('INSERT OR IGNORE INTO events (source, sink, freq) VALUES (?, ?, ?)', model_proc)
    cursor.executemany('INSERT OR IGNORE INTO events (source, sink, freq) VALUES (?, ?, ?)', model_file)
    cursor.executemany('INSERT OR IGNORE INTO events (source, sink, freq) VALUES (?, ?, ?)', model_net)
    cursor.executemany('INSERT OR IGNORE INTO events (source, sink, freq) VALUES (?, ?, ?)', model_nf_read)
    cursor.executemany('INSERT OR IGNORE INTO p2f (source, sink, freq) VALUES (?, ?, ?)', model_file)
    cursor.executemany('INSERT OR IGNORE INTO p2n (source, sink, freq) VALUES (?, ?, ?)', model_net)
    cursor.executemany('INSERT OR IGNORE INTO p2p (source, sink, freq) VALUES (?, ?, ?)', model_proc)
    cursor.executemany('INSERT OR IGNORE INTO proc (source, sink, sink_path, freq) VALUES (?, ?, ?, ?)', proc_proc)
    connection.commit()
    connection.close()


if __name__ == '__main__':
    # log_file_path = sys.argv[1]
    log_file_path = "system_log.txt"
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