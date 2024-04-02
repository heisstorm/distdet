from zss import simple_distance, Node
import json
class Node:
    def __init__(self, name, children=None):
        self.name = name
        self.children = children or []
def load_tree_from_json(file_path):
    with open(file_path, 'r') as file:
        tree = json.load(file)
    return tree

def json_to_node(json_tree):
    name = json_tree["name"]
    children = [json_to_node(child) for child in json_tree.get("children", [])]
    return Node(name, children)

def count_nodes(node):
    if not node.children:
        return 1
    return 1 + sum(count_nodes(child) for child in node.children)

def can_merge(node1, node2):
    if not node1 and not node2:
        return True
    elif not node1 or not node2:
        return False

    # Check if node names are the same
    if node1.name != node2.name:
        return False

    # Recursively check if children can be merged
    children_names1 = {child.name for child in node1.children}
    children_names2 = {child.name for child in node2.children}
    common_children_names = children_names1.intersection(children_names2)

    for common_child_name in common_children_names:
        child1 = next(child for child in node1.children if child.name == common_child_name)
        child2 = next(child for child in node2.children if child.name == common_child_name)
        if not can_merge(child1, child2):
            return False

    # Check if the remaining children can be merged
    remaining_children1 = [child for child in node1.children if child.name not in common_children_names]
    remaining_children2 = [child for child in node2.children if child.name not in common_children_names]

    if len(remaining_children1) != len(remaining_children2):
        return False

    for child1, child2 in zip(remaining_children1, remaining_children2):
        if not can_merge(child1, child2):
            return False

    return True




def main():
    # Load trees from JSON files
    tree1 = load_tree_from_json('ASG/ASG7.json')
    tree2 = load_tree_from_json('ASG/ASG8.json')

    # Convert JSON trees to zss Node objects
    node1 = json_to_node(tree1)
    node2 = json_to_node(tree2)
    print(can_merge(node1, node2))

    # Calculate tree edit distance
    distance = simple_distance(node1, node2)

    # Calculate similarity percentage (assuming higher distance means less similarity)
    max_size = max(count_nodes(node1), count_nodes(node2))
    similarity_percentage = ((max_size - distance) / max_size) * 100

    print(f"Similarity between the trees: {similarity_percentage:.2f}%")

if __name__ == "__main__":
    main()
