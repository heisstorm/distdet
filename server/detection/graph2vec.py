import json
import ssdeep
import os
import re
class TreeNode:
    def __init__(self, name, type, children=None):
        self.name = name
        self.type = type
        self.children = children if children else []

def load_tree_from_json(file_path):
    with open(file_path, 'r') as file:
        tree = json.load(file)
    return tree

def json_to_node(json_tree):
    name = json_tree["name"]
    children = [json_to_node(child) for child in json_tree.get("children", [])]
    return TreeNode(name, '1', children)

def generate_features_non_recursive(root):
    stack = [(root, [root.name])]  # 栈中元素为 (当前节点, 路径)
    features = []

    while stack:
        node, path = stack.pop()

        # 当路径长度大于等于3时，提取特征
        if len(path) >= 3:
            feature_str = ''.join(path[-3:])  # 特征字符串为最后三个节点的名称
            label = ''.join([node.type for _ in range(3)])  # 简化的标签生成逻辑
            features.append({'feature': feature_str, 'label': label})
        elif not node.children:
            # 如果是叶子节点但路径长度小于3，也生成特征
            feature_str = ''.join(path)
            label = ''.join([node.type for _ in range(len(path))])
            features.append({'feature': feature_str, 'label': label})

        # 对子节点按照名称进行排序，然后将它们及其路径添加到栈
        # 确保按照子节点的字符串值从小到大处理
        sorted_children = sorted(node.children, key=lambda child: child.name)
        for child in sorted_children:
            stack.append((child, path + [child.name]))

    return features


def calculate_similarity(features1, features2):
    similar_count = 0
    comparisons = 0

    for feature1 in features1:
        hash1 = ssdeep.hash(feature1['feature'])
        comparisons += 1
        for feature2 in features2:
            hash2 = ssdeep.hash(feature2['feature'])
            similarity = ssdeep.compare(hash1, hash2)
            # 计算相似度，如果超过70%，则认为是相似的
            if similarity > 70:
                similar_count += 1
                break
    # 如果超过50%的特征相似度超过70%，则认为两个进程树可以聚合
    if comparisons > 0 and (similar_count / comparisons) > 0.5:
        return True
    else:
        return False


def numerical_sort(value):
    """
    提取数字用于排序。
    """
    parts = re.match(r"([a-zA-Z]+)(\d+)", value)
    if parts:
        return parts.group(1), int(parts.group(2))
    return value

if __name__ == '__main__':
    features = []
    for dirpath, dirnames, filenames in os.walk('ASG'):
        for filename in sorted(filenames, key=numerical_sort):
            file_path = os.path.join(dirpath, filename)
            if '.DS_Store' in filename:
                os.remove(file_path)
            root = json_to_node(load_tree_from_json(file_path))
            features.append(generate_features_non_recursive(root))
    for i in range(len(features)):
        for j in range(i + 1, len(features)):
            # 获取当前的两个元素
            element_i = features[i]
            element_j = features[j]
            if calculate_similarity(element_i, element_j):
                print("%s %s可以聚合!!!" % (i+1, j+1))
            else:
                # print("%s %s不可以聚合" % (i+1, j+1))
                pass



