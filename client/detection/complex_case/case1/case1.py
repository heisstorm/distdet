import os
import subprocess

LINK = "https://www.dropbox.com/s/xmfeu6gj7ekcrh1/call_others.py?dl=0"
REALSCRIPT = "call_others.py?dl=0"

def generate_fake_file(size, num):
    folder_path = os.getcwd()
    for i in range(num):
        path = os.path.join(folder_path, "{}.fake".format(i))
        with open(path, "wb") as f:
            f.write(os.urandom(num))

if __name__ == "__main__":
#    os.system("ping -c 1 google.com")
#    os.system("ping -c 1 baidu.com")
#    os.system("ping -c 1 yahoo.com")
#    os.system("ping -c 1 zhihu.com")
#    os.system("ping -c 1 youtube.com")
#    os.system("ping -c 1 facebook.com")
#    os.system("ping -c 1 twitter.com")
#    os.system("ping -c 1 amazon.com")
#    os.system("ping -c 1 qq.com")
#    os.system("ping -c 1 quora.com")
    noisy_ips = ["google.com", "baidu.com", "yahoo.com", "zhihu.com", "youtube.com", "facebook.com", "twitter.com",
    "amazon.com", "apple.com", "quora.com"]
    for ip in noisy_ips:
        subprocess.run(["ping", "-c", "1", ip])
    os.system("wget {}".format(LINK))
    os.system("mv {} /home/pxf109/sysrep_test_temp".format(REALSCRIPT))
    os.system("python3 /home/pxf109/sysrep_test_temp/{}".format(REALSCRIPT))
    generate_fake_file(10000, 100)
