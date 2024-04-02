# -* - coding: UTF-8 -* -
# ! /usr/bin/python

import re
import sqlite3
import pandas as pd
import sys

sys.path.append("../../")
from client.training.HST import set_append
from client.training.HST import process_p_model
from client.training.HST import process_f_model
from client.training.HST import process_n_model
from client.training.HST import caculte_start_time
from client.training.HST import procname_path
from client.training.HST import model_file
from client.training.HST import model_proc
from client.training.HST import model_net
from client.training.HST import model_file_proc
from client.training.HST import model_net_proc
from client.training.HST import model_proc_proc
from client.training.HST import proc_proc
from collections import Counter
import math

poi = set()
benign = set()
# 在detection阶段，因为要考虑forward的影响，所以不能只考虑write，也要考虑read
model_nf_read = set()
evict_to_database = True


def process_log_line(line):
    parts = line.split()
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
    model_file_c = pd.read_csv('../training/VMX/Merged/model_file_c.csv')
    model_net_c = pd.read_csv('../training/VMX/Merged/model_net_c.csv')
    model_proc_c = pd.read_csv('../training/VMX/Merged/model_proc_c.csv')

    for l in model_file:
        source, sink, local_freq = l[0], l[1], l[2]
        condition = (model_file_c['source'].astype(str) == source) & (
                model_file_c['sink'].astype(str) == sink)
        # 1. 如果没有精确匹配上
        # 2. 检查相似度
        # 3. 找不到就不检查
        for i in model_file_proc:
            if sink == i[1]:
                if i[0] in procname_path:
                    if procname_path[i[0]] == source:
                        effective_source = i[0]
                        break
                else:
                    effective_source = i[0]
        if not condition.any():
            check_result = check_similarity(source, sink, model_file_c)
            if check_result == 0:
                poi.add((effective_source, sink, 'p2f'))
            else:
                # 如果能匹配上则加上相似度
                benign.add((effective_source, sink, 'p2f', check_result, local_freq))
        else:
            total_freq = model_file_c[condition]['freq'].sum()
            benign.add((effective_source, sink, 'p2f', total_freq, local_freq))


    for l in model_net:
        source, sink, local_freq = l[0], l[1], l[2]
        condition = (model_net_c['source'].astype(str) == source) & (
                model_net_c['sink'].astype(str) == sink)

        for i in model_net_proc:
            if sink == i[1]:
                if i[0] in procname_path:
                    if procname_path[i[0]] == source:
                        effective_source = i[0]
                        break
                else:
                    effective_source = i[0]

        if not condition.any():
            check_result = check_similarity(source, sink, model_net_c)
            if check_result == 0:
                poi.add((effective_source, sink, 'p2n'))
            else:
                # 如果能匹配上则加上相似度
                benign.add((effective_source, sink, 'p2n', check_result, local_freq))
        else:
            total_freq = model_net_c[condition]['freq'].sum()
            benign.add((effective_source, sink, 'p2n', total_freq, local_freq))

    for l in model_proc:
        source, sink, local_freq = l[0], l[1], l[2]
        if not ('<NA>' in sink or '<NA>' in source or sink == '' or source == ''):
            # condition = (model_p_execve_c['source'].astype(str) == source.split('|')[0].strip()) & (
            #         model_p_execve_c['sink'].astype(str) == sink.split('|')[0].strip()) & (
            #                     model_p_execve_c['attr'].astype(str) == mask_path(attr, 0))
            condition = (model_proc_c['source'].astype(str) == source) & (
                    model_proc_c['sink'].astype(str) == sink)

            for i in model_proc_proc:
                if sink == i[1]:
                    if i[0] in procname_path:
                        if procname_path[i[0]] == source:
                            effective_source = i[0]
                            break
                    else:
                        effective_source = i[0]

            if not condition.any():
                check_result = check_similarity(source, sink, model_proc_c)
                if check_result == 0:
                    poi.add((effective_source, sink, 'p2p'))
                else:
                    # 如果能匹配上则加上相似度
                    benign.add((effective_source, sink, 'p2p', check_result, local_freq))
            else:
                total_freq = model_proc_c[condition]['freq'].sum()
                benign.add((effective_source, sink, 'p2p', total_freq, local_freq))

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

    with open('benign.txt', 'w') as file:
        for value in benign:
            file.write(str(value) + '\n')


def check_similarity(source, sink, model):
    if source not in model['source'].values:
        return 0
    else:
        matched_rows = model[model['source'] == source]
        sink_dict = pd.Series(matched_rows['freq'].values, index=matched_rows['sink']).to_dict()
        for sink_s, freq in sink_dict.items():
            if calculate_simlarity(sink, sink_s):
                return freq
        return 0


def calculate_simlarity(sink, sink_s):
    for char in ['/', '.']:
        sink = sink.replace(char, ' ')
        sink_s = sink_s.replace(char, ' ')
    log1_tokens = sink.split()
    log2_tokens = sink_s.split()
    set1 = set(log1_tokens)
    set2 = set(log2_tokens)
    intersection = len(set(set1) & set(set2))
    union = len(set(set1) | set(set2))
    Jaccard = intersection / union

    log1_counter = Counter(log1_tokens)
    log2_counter = Counter(log2_tokens)
    all_items = set(log1_counter.keys()) | set(log2_counter.keys())
    vector1 = [log1_counter.get(k, 0) for k in all_items]
    vector2 = [log2_counter.get(k, 0) for k in all_items]
    dot_product = sum(a * b for a, b in zip(vector1, vector2))
    magnitude1 = math.sqrt(sum(a * a for a in vector1))
    magnitude2 = math.sqrt(sum(b * b for b in vector2))
    Cosine = dot_product / (magnitude1 * magnitude2)

    common_tokens = log1_counter & log2_counter
    total_common = sum(common_tokens.values())
    ori_nlp = total_common / max(len(log1_tokens), len(log2_tokens))
    if Cosine >= 0.75:
        return True
    else:
        # print("log1:" + sink + ", " + "log2:" + sink_s)
        # print("Jaccard:" + str(Jaccard))
        # print("Cosine:" + str(Cosine))
        # print("ori_nlp:" + str(ori_nlp))
        return False


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
    log_file_path = "VMX/vm1/system_log.txt"
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