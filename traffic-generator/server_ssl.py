import socket
import threading
from concurrent.futures import ThreadPoolExecutor
import multiprocessing
import re
import ssl


host = '193.168.10.3'
port = 443
role = 'server'

# server_message = "This is server" * 5000
# client_message = "This is client" * 5000

# server_message = "This is server" * 5
# client_message = "This is client" * 5


client_message = 'HEAD / HTTP/1.0\r\nHost: 193.168.10.3\r\nUser-Agent: HTTPing v2.5\r\n\r\n'
server_message = 'HTTP/1.1 200 OK\r\nServer: www.office.com\r\nDate: Fri, 07 Jan 2022 05:43:22 GMT\r\nConnection: close\r\n\r\n'
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
            # if
            print(data)
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
    sock.listen(max_cocurrent_thread)
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


def multi_ssl_thread_main(host, port):
    global total_connections
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain('/root/devtest_micro-service/sish_root_ca/mycert.pem',
                            '/root/devtest_micro-service/sish_root_ca/mycert.key')
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.bind((host, port))
        sock.listen(max_cocurrent_thread)
        with ThreadPoolExecutor(max_workers=max_cocurrent_thread) as pool:
            with context.wrap_socket(sock, server_side=True) as ssock:
                while True:
                    try:
                        new_sock, address = ssock.accept()
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


ssl_option = True
if ssl_option == True:
    multi_ssl_thread_main(host, port)
else:
    multi_thread_main(host, port)
# multi_process_main(host, port)


# sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout
# mycert.key -out mycert.pem
