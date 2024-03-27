"""
This file is used to write random binary data to a specific location(home/.../sysrep_random)
"""
import os

HOME = os.path.expanduser("~")


def write_random_data_to_file(file_location, size=50000000):
    with open(file_location, "wb") as file:
        file.write(os.urandom(size))


if __name__ == "__main__":
    write_random_data_to_file(os.path.join(HOME, "sysrep_random"))