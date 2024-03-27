# -* - coding: UTF-8 -* -
# ! /usr/bin/python
import json
import os
import sqlite3
import shutil

conn = sqlite3.connect('event_caching.db')
cursor = conn.cursor()
class Process_Lineage:

    # label 0 代表 上下文关联的事件，一般视作普通事件
    # label 1 代表 告警
    # frequency 节点出现的次数
    # p2p 代表前N个process出边，frequency, label 元组
    # p2f 代表前N个file出边, frequency, label 元组
    # p2n 代表前N个network出边, frequency, label 元组
    # 是否还是分开储存比较好 答案 没区别
    # 先构建tree，再附着
    def __init__(self, name):
        self.name = name
        self.children = []
        self.label = 0
        self.freq = 0
        self.exe_path = ""
        self.p2p = []
        self.p2f = []
        self.p2n = []

    def add_child(self, child):
        self.children.append(child)

    def add_p2p(self, child):
        self.p2p.append(child)

    def add_p2f(self, child):
        self.p2f.append(child)

    def add_p2n(self, child):
        self.p2n.append(child)

    def to_dict(self):
        result = {
            "name": self.name,
            "label": self.label,
            "freq": self.freq
        }
        if self.children:
            result["children"] = [child.to_dict() for child in self.children]
        if self.p2p:
            result["p2p"] = [child.to_dict() for child in self.p2p]
        if self.p2f:
            result["p2f"] = [child.to_dict() for child in self.p2f]
        if self.p2n:
            result["p2n"] = [child.to_dict() for child in self.p2n]
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
        sql_query = "SELECT * FROM proc WHERE sink=?"
        parameters = (name.replace('\'', ''),)
        cursor.execute(sql_query, parameters)
        results = cursor.fetchall()
        if not results:
            break
        # 实验数据得出不止有一个祖先，因为pid归并成为路径的原因, 需要改进
        id, source, sink, sink_proc, freq = results[0]
        source_node = Process_Lineage(source)
        source_node.children = [current_node]
        current_node.freq = int(freq)
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
        sql_query = "SELECT * FROM proc WHERE source=?"
        parameters = (name.replace('\'', ''),)
        cursor.execute(sql_query, parameters)
        results = cursor.fetchall()
        sink_dict = {}
        for row in results:
            id, source, sink, sink_path, freq = row
            # 要么添加叶子节点，要么添加普通节点
            # 编辑距离在此处添加，节点的编辑距离?
            if sink in sink_dict.keys():
                sink_dict[sink] = sink_dict[sink]+int(freq)
            else:
                sink_dict[sink] = int(freq)
        #上下文节点，良性节点
        for name, freq in sink_dict.items():
            c = Process_Lineage(name)
            c.frequency = int(freq)
            c.label = 0
            current_node.add_child(c)
            current_node.freq += int(freq)
        stack.extend((child, level + 1) for child in reversed(current_node.children))
    return root


def findNoutedges(root, n):
    root_ori = root
    query = "SELECT sink, sink_path FROM proc"
    cursor.execute(query)
    results = cursor.fetchall()
    sink_dict = {sink: sink_path for sink, sink_path in results}
    sink_dict_tmp = {}
    for key, value in sink_dict.items():
        key_l = key.split(' | ')[0]
        if key_l not in sink_dict_tmp:
            sink_dict_tmp[key_l] = value
    sink_dict = sink_dict_tmp
    stack = [root]
    while stack:
        current_node = stack.pop()
        name = current_node.name
        if name in poi_set:
            current_node.label = 1
        if ' | ' not in name or name.split(' | ')[0] not in sink_dict:
            continue
        path = sink_dict[name.split(' | ')[0]]
        current_node.path = path
        sql_query = "SELECT * FROM p2f WHERE source =? LIMIT ?"
        parameters = (path, n)
        cursor.execute(sql_query, parameters)
        results = cursor.fetchall()
        for r in results:
            id, source, sink, freq = r
            sink = Process_Lineage(sink)
            sink.freq = int(freq)
            if sink.name in poi_set:
                sink.label = 1
            else:
                sink.label = 0
            current_node.add_p2f(sink)
        sql_query = "SELECT * FROM p2n WHERE source =? LIMIT ?"
        cursor.execute(sql_query, parameters)
        results = cursor.fetchall()
        for r in results:
            id, source, sink, freq = r
            sink = Process_Lineage(sink)
            sink.freq = int(freq)
            if sink.name in poi_set:
                sink.label = 1
            else:
                sink.label = 0
            current_node.add_p2n(sink)
        sql_query = "SELECT * FROM p2p WHERE source =? LIMIT ?"
        cursor.execute(sql_query, parameters)
        results = cursor.fetchall()
        for r in results:
            id, source, sink, freq = r
            sink = Process_Lineage(sink)
            sink.freq = int(freq)
            if sink.name in poi_set:
                sink.label = 1
            else:
                sink.label = 0
            current_node.add_p2p(sink)
        # Add children of current node to the stack
        stack.extend(current_node.children)
    return root_ori

poi_set = set()

if __name__ == '__main__':
    # 每个poi对应一个ASG，放在ASG文件夹下
    shutil.rmtree('ASG')
    os.mkdir('ASG')
    # 字符串的 list
    with open('poi.txt', 'r') as file:
        pois = [line.strip() for line in file]

    # 一个进程pid为一个起点，把不同的子节点/频率合并起来
    result = {}
    for i in pois:
        # 将进程名字pid完全相同的poi合并到同一个树下
        s = i.lstrip('(').rstrip(')').split(",")
        freq = int(s[0])
        source = s[1].replace("\'", "").strip()
        sink = s[2].replace("\'", "").strip()
        type = s[3].replace("\'", "").strip()
        sink = Process_Lineage(sink)
        sink.label = 1
        sink.freq = freq
        poi_set.add(sink)
        if source not in poi_set:
            poi_set.add(source)
            root = Process_Lineage(source)
            root.freq = freq
            root.label = 1
            # add child 是一个node 不是字符串
            if type == 'p2f':
                root.add_p2f(sink)
            elif type == 'p2p':
                root.add_p2p(sink)
            else:
                root.add_p2n(sink)
            result[source] = root
        else:
            current_root = result[source]
            if type == 'p2f':
                current_root.add_p2f(sink)
            elif type == 'p2p':
                current_root.add_p2p(sink)
            else:
                current_root.add_p2n(sink)
            current_root.freq += freq

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
        root = findNoutedges(root, n)
        process_tree_dict = root.to_dict()
        with open('ASG/ASG%s.json' % ASG_count, 'w') as file:
            json.dump(process_tree_dict, file, indent=4)
        print("-----------%s-----------" % ASG_count)
        ASG_count = ASG_count + 1
    pass
