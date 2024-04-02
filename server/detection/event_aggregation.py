import os
import re
from collections import Counter
import math
import json
class TreeNode:
    def __init__(self, name, label, freq, p2p=None, p2f=None, p2n=None, children=None):
        self.name = name
        self.label = label
        self.freq = freq
        self.children = children if children else []
        self.p2p = p2p if p2p else []
        self.p2f = p2f if p2f else []
        self.p2n = p2n if p2n else []

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

def load_tree_from_json(file_path):
    with open(file_path, 'r') as file:
        tree = json.load(file)
    return json_to_node(tree)
def numerical_sort(value):
    parts = re.match(r"([a-z]+)(\d*)", value, re.I)
    if parts:
        text, number = parts.groups()
        return (text, int(number) if number else 0)
    return (value, 0)

def json_to_node(json_tree):
    name = json_tree["name"]
    label = json_tree["label"]
    freq = json_tree["freq"]
    p2p = [json_to_node(child) for child in json_tree.get("p2p", [])]
    p2f = [json_to_node(child) for child in json_tree.get("p2f", [])]
    p2n = [json_to_node(child) for child in json_tree.get("p2n", [])]
    children = [json_to_node(child) for child in json_tree.get("children", [])]
    return TreeNode(name, label, freq, p2p, p2f, p2n, children)

def cosine_similarity(str1, str2):
    for char in ['/', '.']:
        sink = str1.replace(char, ' ')
        sink_s = str2.replace(char, ' ')
    log1_tokens = sink.split()
    log2_tokens = sink_s.split()
    log1_counter = Counter(log1_tokens)
    log2_counter = Counter(log2_tokens)
    all_items = set(log1_counter.keys()) | set(log2_counter.keys())
    vector1 = [log1_counter.get(k, 0) for k in all_items]
    vector2 = [log2_counter.get(k, 0) for k in all_items]
    dot_product = sum(a * b for a, b in zip(vector1, vector2))
    magnitude1 = math.sqrt(sum(a * a for a in vector1))
    magnitude2 = math.sqrt(sum(b * b for b in vector2))
    if magnitude1 == 0 and magnitude2 == 0:
        return 0.999
    if magnitude1 == 0 or magnitude2 == 0:
        return 0
    Cosine = dot_product / (magnitude1 * magnitude2)
    return Cosine

def merge_nodes(nodes, child_type):
    merged_nodes = []
    skip_indices = set()
    if child_type == 'p2p':
        cosine_threshold = 0.99
    elif child_type == 'p2p':
        cosine_threshold = 0.85
    else:
        cosine_threshold = 0.85

    for i, node1 in enumerate(nodes):
        if i in skip_indices:
            continue
        for j, node2 in enumerate(nodes[i+1:], start=i+1):
            if j in skip_indices:
                continue
            if node1.label == node2.label and cosine_similarity(node1.name, node2.name) >= cosine_threshold:
                node1.freq += node2.freq
                skip_indices.add(j)
        merged_nodes.append(node1)
    return merged_nodes

def process_tree_node(node):
    # Iterate over TreeNode instance attributes
    for child_type in ['p2p', 'p2f', 'p2n']:
        children = getattr(node, child_type)
        merged_children = merge_nodes(children, child_type)
        setattr(node, child_type, merged_children)

    for child_node in node.children:
        process_tree_node(child_node)


if __name__ == '__main__':
    for dirpath, dirnames, filenames in os.walk('ASG'):
        for filename in sorted(filenames, key=numerical_sort):
            file_path = os.path.join(dirpath, filename)
            if '.DS_Store' in filename:
                os.remove(file_path)
            root = load_tree_from_json(file_path)
            process_tree_node(root)
            with open(file_path, 'w') as json_file:
                json.dump(root.to_dict(), json_file, indent=4)

