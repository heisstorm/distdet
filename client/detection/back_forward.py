# -* - coding: UTF-8 -* -
# ! /usr/bin/python
import sqlite3
from decimal import Decimal
from queue import Queue
import graphviz

conn = sqlite3.connect('event_caching.db')
cursor = conn.cursor()

ASG = set()


def backward(poi, x):
    bfsqueue = Queue(0)
    source = poi.split("->")[0].strip()
    sink = poi.split("->")[1].strip()
    if " | " in source and " | " in sink:
        sql_query = "SELECT * FROM events WHERE source='%s' AND sink='%s'" % (sink, source)
        cursor.execute(sql_query)
        results = cursor.fetchall()
        for row in results:
            # 应该考虑到很多条
            id, source, sink, time, attr = row
            bfsqueue.put([id, source, sink, time, attr])
        while not bfsqueue.empty():
            # 取出第一个
            cur = bfsqueue.get()
            cur_id = cur[0]
            cur_task_source = cur[1]
            cur_task_sink = cur[2]
            ASG.add(cur_task_sink + " -> " + cur_task_source)
            print(cur_task_sink + "--------->" + cur_task_source)
            if x == 0:
                break
            x = x - 1

            cur_task_time = cur[3]
            sql_query = "SELECT * FROM events WHERE source='%s'" % (cur_task_sink)
            cursor.execute(sql_query)
            results = cursor.fetchall()
            for row in results:
                id, source, sink, time, attr = row
                if id != cur_id:
                    if time_compare(time.split('-')[0], cur_task_time.split('-')[1]):
                        bfsqueue.put([id, source, sink, time, attr])


def time_compare(t1, t2):
    # true if t1<t2
    t1_int = Decimal(t1.split(':')[0])
    t1_dec = Decimal(t1.split(':')[1])
    t2_int = Decimal(t2.split(':')[0])
    t2_dec = Decimal(t2.split(':')[1])
    if t1_int < t2_int:
        return True
    elif t1_int == t2_int:
        if t1_dec < t2_dec:
            return True
    else:
        return False


def forward(poi, x):
    bfsqueue = Queue(0)
    source = poi.split("->")[0].strip()
    sink = poi.split("->")[1].strip()
    if " | " in source and " | " in sink:
        sql_query = "SELECT * FROM events WHERE source='%s' AND sink='%s'" % (sink, source)
        cursor.execute(sql_query)
        results = cursor.fetchall()
        for row in results:
            # 应该考虑到很多条
            id, source, sink, time, attr = row
            bfsqueue.put([id, source, sink, time, attr])
        while not bfsqueue.empty():
            # 取出第一个
            cur = bfsqueue.get()
            cur_id = cur[0]
            cur_task_source = cur[1]
            cur_task_sink = cur[2]

            ASG.add(cur_task_sink + " -> " + cur_task_source)
            print(cur_task_sink + "--------->" + cur_task_source)
            if x == 0:
                break
            x = x - 1

            cur_task_time = cur[3]
            sql_query = "SELECT * FROM events WHERE sink='%s'" % (cur_task_source)
            cursor.execute(sql_query)
            results = cursor.fetchall()
            for row in results:
                id, source, sink, time, attr = row
                if id != cur_id:
                    if time_compare(cur_task_time.split('-')[0], time.split('-')[1]):
                        bfsqueue.put([id, source, sink, time, attr])


def visualize_hierarchy(process_relationships, output_filename='ASG'):
    dot = graphviz.Digraph(comment='ASG')

    for relationship in process_relationships:
        parent, child = relationship.split(" -> ")
        dot.node(parent.strip())
        dot.node(child.strip())
        dot.edge(parent.strip(), child.strip())

    # Save the DOT source to a file
    dot.save(output_filename + '.dot')

    # Generate a PNG image
    dot.render(output_filename, format='png', cleanup=True)


if __name__ == '__main__':
    # 字符串的 list
    with open('poi.txt', 'r') as file:
        pois = [line.strip() for line in file]
    x = 2
    for poi in pois:
        backward(poi, x)
        print("----------------------")
        forward(poi, x)
    visualize_hierarchy(ASG)
