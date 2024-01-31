# -* - coding: UTF-8 -* -
# ! /usr/bin/python
import requests
client_ip_pool = ["10.218.111.86",
                  "10.218.105.30",
                  "10.218.105.87"]

client_file_pool = ["proc_attr_token_bag_counter_client.csv",
                    "proc_attr_token_bag_client.csv",
                    "subject_proc_object_proc_client.csv",
                    "oper_proc_cient.csv"]

def pull_file():
    for current_ip in client_ip_pool:
        try:
            for file_name in client_file_pool:
                file_name_client = "/home/storm/Documents/" + file_name
                url = "http://%s%s" % (current_ip, file_name_client)
                print(url)
                file_name_server = file_name.replace("client", "server") + "[" + current_ip + "]"
                response = requests.get(url)
                if response.status_code == 200:
                    with open(file_name_server, 'wb') as file:
                        file.write(response.content)
                    print("write success" + file_name_server)
        except:
            print(current_ip + " failed")
def push_file():
    pass

if __name__ == '__main__':
    pull_file()