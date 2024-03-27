"""
dropbox link: https://www.dropbox.com/s/qg6qzyuaxcj6rph/write_home.py?dl=0
"""

import os
def write_paths_to_a_file(folder_path, write_dst):
    file_list = []
    for f in os.listdir(folder_path):
        file_list.append(f)
    with open(os.path.join(write_dst, "paths.txt"), "w") as f:
        f.write(str(file_list))


if __name__ == "__main__":
    write_paths_to_a_file("/home/pxf109", "/home/pxf109/sysrep_test_temp")