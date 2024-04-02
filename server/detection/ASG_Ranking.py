# -* - coding: UTF-8 -* -
# ! /usr/bin/python
import json
import os
import re
import pandas as pd
import shutil

average_freq_p2p = {}
average_freq_p2f = {}
average_freq_p2n = {}


def numerical_sort(value):
    """
    提取数字用于排序。
    """
    parts = re.match(r"([a-zA-Z]+)(\d+)", value)
    if parts:
        return parts.group(1), int(parts.group(2))
    return value


def load_tree_from_json(file_path):
    with open(file_path, 'r') as file:
        tree = json.load(file)
    return tree


def calculate_average_freq():
    model_file_c = pd.read_csv('../../client/training/merged/model_file_c.csv')
    model_net_c = pd.read_csv('../../client/training/merged/model_net_c.csv')
    model_proc_c = pd.read_csv('../../client/training/merged/model_proc_c.csv')
    average_freq_p2p_count = {}
    average_freq_p2f_count = {}
    average_freq_p2n_count = {}
    for index, row in model_file_c.iterrows():
        s = row['source']
        f = int(row['freq'])
        if s in average_freq_p2f.keys():
            average_freq_p2f[s] = average_freq_p2f[s] + f
            average_freq_p2f_count[s] += 1
        else:
            average_freq_p2f_count[s] = 1
            average_freq_p2f[s] = f
    for index, row in model_net_c.iterrows():
        s = row['source']
        f = int(row['freq'])
        if s in average_freq_p2n.keys():
            average_freq_p2n[s] = average_freq_p2n[s] + f
            average_freq_p2n_count[s] += 1
        else:
            average_freq_p2n[s] = f
            average_freq_p2n_count[s] = 1
    for index, row in model_proc_c.iterrows():
        s = row['source']
        f = int(row['freq'])
        if s in average_freq_p2p.keys():
            average_freq_p2p[s] = average_freq_p2p[s] + f
            average_freq_p2p_count[s] += 1
        else:
            average_freq_p2p[s] = f
            average_freq_p2p_count[s] = 1
    for i in average_freq_p2f.keys():
        average_freq_p2f[i] = average_freq_p2f[i] / average_freq_p2f_count[i]
    for i in average_freq_p2p.keys():
        average_freq_p2p[i] = average_freq_p2p[i] / average_freq_p2p_count[i]
    for i in average_freq_p2n.keys():
        average_freq_p2n[i] = average_freq_p2n[i] / average_freq_p2n_count[i]


def calculate_score(root):
    alarm_sum = 0
    alarm_count = 0
    benign_sum = 0
    benign_count = 0
    stack = [root]
    while stack:
        current_node = stack.pop()

        if 'p2p' in current_node.keys():
            p2p = current_node['p2p']
            for p in p2p:
                freq = int(p['freq'])
                if p['label'] == 1:
                    alarm_count += 1
                    alarm_sum += freq
                else:
                    benign_count += 1
                    if p['name'].rstrip('.') in average_freq_p2p.keys():
                        if freq < average_freq_p2p[p['name'].rstrip('.')]:
                            benign_sum += 1
        if 'p2f' in current_node.keys():
            p2f = current_node['p2f']
            for p in p2f:
                freq = int(p['freq'])
                if p['label'] == 1:
                    alarm_count += 1
                    alarm_sum += freq
                else:
                    benign_count += 1
                    if p['name'].rstrip('.') in average_freq_p2f.keys():
                        if freq < average_freq_p2f[p['name'].rstrip('.')]:
                            benign_sum += 1
        if 'p2n' in current_node.keys():
            p2n = current_node['p2n']
            for p in p2n:
                freq = int(p['freq'])
                if p['label'] == 1:
                    alarm_count += 1
                    alarm_sum += freq
                else:
                    benign_count += 1
                    if p['name'].rstrip('.') in average_freq_p2n.keys():
                        if freq < average_freq_p2n[p['name'].rstrip('.')]:
                            benign_sum += 1
        if 'children' in current_node:
            stack.extend(current_node['children'])

    if benign_count == 0:
        if alarm_count <= 2:
            return 0.9*(alarm_sum / alarm_count) + 0
        else:
            return 0.1 * (alarm_sum / alarm_count) + 0
    else:
        if alarm_count <= 2:
            return 0.9*(alarm_sum / alarm_count) + benign_sum / benign_count
        else:
            return 0.1 * (alarm_sum / alarm_count) + benign_sum / benign_count


if __name__ == '__main__':
    features = []
    calculate_average_freq()
    score_list = {}
    for dirpath, dirnames, filenames in os.walk('ASG'):
        for filename in sorted(filenames, key=numerical_sort):
            file_path = os.path.join(dirpath, filename)
            if '.DS_Store' in filename:
                os.remove(file_path)
            root = load_tree_from_json(file_path)
            score = calculate_score(root)
            score_list[file_path]=score
    sorted_data = dict(sorted(score_list.items(), key=lambda item: item[1], reverse=True))
    Threshold = 0.14
    if os.path.exists("malicious_ASG"):
        shutil.rmtree("malicious_ASG")
        os.mkdir("malicious_ASG")
    if os.path.exists("bengin_ASG"):
        shutil.rmtree("bengin_ASG")
        os.mkdir("bengin_ASG")

    for key, item in sorted_data.items():
        if item > Threshold:
            shutil.copy(key, os.path.join("malicious_ASG", os.path.basename(key)))
        else:
            shutil.copy(key, os.path.join("bengin_ASG", os.path.basename(key)))

    special_char = ['pxf109', 'case1', 'case2', 'case3', 'case4', 'case5', 'case6', 'ping_others.sh', '/case/']
    True_Positive = 0
    False_Positive = 0
    True_Negative = 0
    False_Negative = 0
    for dirpath, dirnames, filenames in os.walk('malicious_ASG'):
        for filename in filenames:
            file_path = os.path.join(dirpath, filename)
            if '.DS_Store' in filename:
                os.remove(file_path)
                continue
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                file_content = file.read()
                if any(special in file_content for special in special_char):
                    True_Positive += 1
                    continue
                else:
                    False_Positive += 1

    for dirpath, dirnames, filenames in os.walk('bengin_ASG'):
        for filename in filenames:
            file_path = os.path.join(dirpath, filename)
            if '.DS_Store' in filename:
                os.remove(file_path)
                continue
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                file_content = file.read()
                if any(special in file_content for special in special_char):
                    False_Negative += 1
                    continue
                else:
                    True_Negative += 1
    Precision = True_Positive/(True_Positive+False_Positive)
    Recall = True_Positive/(True_Positive+False_Negative)
    F1_score = 2*(Precision*Recall)/(Precision+Recall)
    print("Precision: %s" % Precision)
    print("Recall: %s" % Recall)
    print("F1_score: %s" % F1_score)


