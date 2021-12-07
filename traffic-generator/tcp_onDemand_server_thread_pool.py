import socket
import threading
from concurrent.futures import ThreadPoolExecutor
import multiprocessing


host = '193.168.10.3'
port = 8111
role = 'server'

server_message = "This is server" * 5
client_message = "This is client" * 5

total_connections = 0
max_cocurrent_thread = 2000
child_process_num = 2


client_message_len = len(client_message)
server_message_len = len(server_message)
if role == 'client':
    data_len = server_message_len
    send_message = client_message
else:
    data_len = client_message_len
    send_message = server_message


def my_client(sock, address, client_id):
    print("ID:{} New connectoin!".format(client_id))
    recv_len = 0
    while True:
        try:
            data = sock.recv(4096)
            recv_len += len(data)
        except:
            sock.close()
            break
        if recv_len >= data_len:
            sock.sendall(str.encode(send_message))
            break
    sock.close()


def multi_thread_main(host, port):
    global total_connections
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((host, port))
    sock.listen(5)
    with ThreadPoolExecutor(max_workers=max_cocurrent_thread) as pool:
        while True:
            # print("Main thread listening!")
            try:
                new_sock, address = sock.accept()
            except Exception as e:
                print("." * 100 + "Accept failed!")
            else:
                total_connections = total_connections + 1
                future1 = pool.submit(
                    my_client, new_sock, address, total_connections)


def multi_process_main(host, port):
    print("Main Process")
    pool = multiprocessing.Pool(processes=child_process_num)
    for i in range(child_process_num):
        pool.apply_async(multi_thread_main, (host, port + i))

    pool.close()
    pool.join()


multi_thread_main(host, port)
# multi_process_main(host, port)
