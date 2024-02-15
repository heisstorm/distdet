# -* - coding: UTF-8 -* -
# ! /usr/bin/python
import json
import os
import sqlite3
import shutil

conn = sqlite3.connect('event_caching.db')
cursor = conn.cursor()

ASG = {}

class Process_Lineage:
    def __init__(self, name):
        self.name = name
        self.children = []

    def add_child(self, child):
        self.children.append(child)

    def to_dict(self):
        result = {
            "name": self.name,
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
        stack.append([source_node, level+1])
    return current_node

def forward(poi, y):
    poi = poi.lstrip('(').rstrip(')')
    source = poi.split(",")[1].strip()
    sink = poi.split(",")[2].strip()
    if ' | ' in sink:
        root = Process_Lineage(sink)
    else:
        root = Process_Lineage(source)
    stack = [(root, 0)]
    while stack:
        current_node, level = stack.pop()
        name = current_node.name
        if level > y:
            break
        sql_query = "SELECT * FROM events WHERE source=? AND sink LIKE ?"
        parameters = (name.replace('\'', ''), '% | %')
        cursor.execute(sql_query, parameters)
        results = cursor.fetchall()
        sink_set = set()
        for row in results:
            id, time, source, sink, attr = row
            sink_set.add(sink)
        children = []
        for i in list(sink_set):
            children.append(Process_Lineage(i))
        current_node.children = children

        stack.extend((child, level + 1) for child in reversed(current_node.children))
    return root


if __name__ == '__main__':
    # 每个poi对应一个ASG，放在ASG文件夹下
    shutil.rmtree('ASG')
    os.mkdir('ASG')
    # 字符串的 list
    with open('poi.txt', 'r') as file:
        pois = [line.strip() for line in file]

    x = 12
    y = 2
    n = 15
    ASG_count = 1
    for poi in pois:
        ASG.clear()
        root_f = forward(poi, y)
        root = backward(root_f, x)
        process_tree_dict = root.to_dict()
        with open('ASG/ASG%s.json' % ASG_count, 'w') as file:
            json.dump(process_tree_dict, file, indent=2)
        print("-----------%s-----------" % ASG_count)
        ASG_count = ASG_count + 1
    pass
