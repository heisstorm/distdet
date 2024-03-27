import os

def read_exp_file(path, target_path):
    target_file = open(target_path, "w+")
    with open(path, "r") as file:
        for l in file.readline():
            target_file.write(l)
    target_file.close()

if __name__ == "__main__":
    read_exp_file("sysrep_exp_data.txt?dl=0", "target_file")
