# -* - coding: UTF-8 -* -
# ! /usr/bin/python
import json
import os
import sqlite3
import shutil

conn = sqlite3.connect('event_caching.db')
cursor = conn.cursor()

alarm_label = set()

class Process_Lineage:

    # label 0 代表 上下文关联的事件，一般视作普通事件
    # label 1 代表 告警
    # frequency 节点出现的次数
    # p2p 代表前N个process出边，frequency, label 元组
    # p2f 代表前N个file出边, frequency, label 元组
    # p2n 代表前N个network出边, frequency, label 元组
    def __init__(self, name):
        self.name = name
        self.children = []
        self.label = 0
        self.frequency = 0
        self.p2p = []
        self.p2f = []
        self.p2n = []

    def add_child(self, child):
        self.children.append(child)

    def to_dict(self):
        result = {
            "name": self.name,
            "label": self.label,
            "frequency": self.frequency
        }
        if self.children:
            result["children"] = [child.to_dict() for child in self.children]
        return result


def add(ASG, element):
    if element in ASG:
        ASG[element] += 1
    else:
        ASG[element] = 1


def backward(root_f, x):
    stack = [(root_f, 0)]
    current_node = ""
    while stack:
        # 取出第一个
        current_node, level = stack.pop()
        name = current_node.name
        if level >= x:
            break
        sql_query = "SELECT * FROM events WHERE sink=? AND source LIKE ?"
        parameters = (name.replace('\'', ''), '% | %')
        cursor.execute(sql_query, parameters)
        results = cursor.fetchall()
        if not results:
            break
        id, time, source, sink, attr = results[0]
        source_node = Process_Lineage(source)
        source_node.children = [current_node]
        stack.append([source_node, level + 1])
    return current_node


def forward(poi, y):
    root = poi
    stack = [(root, 0)]
    while stack:
        current_node, level = stack.pop()
        name = current_node.name
        if level > y:
            break
        sql_query = "SELECT * FROM events WHERE source=? AND sink LIKE ?"
        parameters = (name.replace('\'', ''), '% | %')
        # sql_query = "SELECT * FROM events WHERE source=?"
        # parameters = (name.replace('\'', ''),)
        cursor.execute(sql_query, parameters)
        results = cursor.fetchall()
        sink_dict = {}
        for row in results:
            id, time, source, sink, attr = row
            # 要么添加叶子节点，要么添加普通节点
            # 编辑距离在此处添加，节点的编辑距离?
            if sink in alarm_label:
                continue
            else:
                if sink in sink_dict.keys():
                    sink_dict[sink] = sink_dict[sink]+1
                else:
                    sink_dict[sink] = 1
        #上下文节点，良性节点
        for name, freq in sink_dict.items():
            c = Process_Lineage(name)
            c.frequency = freq
            c.label = 0
            current_node.add_child(c)
            current_node.frequency += freq
        stack.extend((child, level + 1) for child in reversed(current_node.children))
    return root


if __name__ == '__main__':
    # 每个poi对应一个ASG，放在ASG文件夹下
    shutil.rmtree('ASG')
    os.mkdir('ASG')
    # 字符串的 list
    with open('poi.txt', 'r') as file:
        pois = [line.strip() for line in file]

    # experiment: 将进程名字pid完全相同的合并, 是对的
    # 一个进程pid为一个起点，把不同的子节点/频率合并起来
    poi_set = set()
    result = {}
    for i in pois:
        s = i.lstrip('(').rstrip(')').split(",")
        frequency = int(s[0])
        name = s[1].replace("\'", "").strip()
        child_s = s[2].replace("\'", "").strip()
        child = Process_Lineage(child_s)
        child.label = 1
        child.frequency = frequency
        alarm_label.add(name)
        alarm_label.add(child_s)
        if name not in poi_set:
            poi_set.add(name)
            root = Process_Lineage(name)
            # add child 是一个node 不是字符串
            root.add_child(child)
            root.label = 1
            root.frequency = frequency
            result[name] = root
        else:
            current_root = result[name]
            current_root.add_child(child)
            current_root.frequency += frequency

    x = 12
    y = 2
    n = 15
    ASG_count = 1
    # 白名单机制
    white_list = []
    for poi in result.values():
        if poi in white_list:
            continue
        root_f = forward(poi, y)
        root = backward(root_f, x)
        process_tree_dict = root.to_dict()
        with open('ASG/ASG%s.json' % ASG_count, 'w') as file:
            json.dump(process_tree_dict, file, indent=4)
        print("-----------%s-----------" % ASG_count)
        ASG_count = ASG_count + 1
    pass
