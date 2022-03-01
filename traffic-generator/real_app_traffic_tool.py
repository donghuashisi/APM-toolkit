import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor
import multiprocessing

######################################
##### Parameters you can modify ######
######################################
TCP_MSS = 400
new_thread_gap = 0.001
client_lock = threading.Lock()
total_connect = 0
cur_child_thread = 0
failed_connect = 0
done_connect = 0

server_max_cocurrent_thread = 100
########## client #######


class Client(threading.Thread):

    def __init__(self, host, port, ssl_enable=False):
        super(Client, self).__init__()
        self.host = host
        self.port = port
        self.ssl_enable = ssl_enable

    def run(self):
        global total_connect, cur_child_thread, failed_connect, done_connect
        host = self.host
        port = self.port

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, TCP_MSS)
        if self.ssl_enable == True:
            ########################
            ###Wrap tcp with SSL ###
            ########################
            context = ssl.create_default_context()
            context.load_verify_locations(
                "/root/devtest_micro-service/sish_root_ca/mycert.pem")
            sock = context.wrap_socket(sock,
                                       # cert_reqs=ssl.CERT_REQUIRED,
                                       server_hostname="www.cisco_test.com")
        sock.connect((host, port))

        ########################
        ### Update global value#
        ########################
        client_lock.acquire()
        cur_child_thread = cur_child_thread + 1
        total_connect = total_connect + 1
        my_id = total_connect
        print("Child :{} Created! Current thread num:{}".format(my_id,
                                                                cur_child_thread))
        client_lock.release()
        ########################
        ### Send message now   #
        ########################
        try:
            sock.sendall(str.encode(client_send_message))
        except:
            #####################################
            ### Send failed. Update global value#
            #####################################
            client_lock.acquire()
            cur_child_thread = cur_child_thread - 1
            failed_connect = failed_connect + 1
            done_connect += 1
            print(
                "*" * 50 + "Exception!!  Failed to Send! Child Thread:{}".format(my_id, cur_child_thread))
            client_lock.release()
            ########################
            return
        ################################
        ### Wait message from server   #
        ################################
        recv_len = 0
        while True:
            try:
                data = sock.recv(4096)
                recv_len += len(data)
            except:
                ########################################
                ### Receive failed. Update global value#
                ########################################
                client_lock.acquire()
                print(
                    "Exception!!Failed to Receive! Child Thread:{}!".format(my_id))
                failed_connect = failed_connect + 1
                cur_child_thread = cur_child_thread - 1
                done_connect += 1
                client_lock.release()
                return
            if recv_len >= client_data_len:
                break
        sock.close()
        ################################################
        ### Communication finished. Uodate global value#
        ################################################
        client_lock.acquire()
        print("Child :{} Finished! Current thread num:{}".format(my_id,
                                                                 cur_child_thread))
        cur_child_thread = cur_child_thread - 1
        done_connect += 1
        client_lock.release()


def client_multi_thread_main(host, port, ssl_enable):
    global total_connect, cur_child_thread, failed_connect, done_connect
    start_time = time.asctime(time.localtime(time.time()))
    submit_job = 0
    base_port = port
    while True:
        ########################
        ### Update global value#
        ########################
        client_lock.acquire()
        now_total_connect = total_connect
        now_cur_child_thread = cur_child_thread
        now_done_connect = done_connect
        client_lock.release()
        if now_total_connect > max_total_connect:
            #####################################
            ### Total connection finished  ######
            #####################################
            break
        #############################
        ###  New job submit  ########
        #############################
        if now_cur_child_thread >= max_cur_thread:
            #############################
            ### co-current reach max  ###
            #############################
            time.sleep(new_thread_gap)
            continue

        #############################
        ### co-current < max  #######
        #############################
        pending_connect = submit_job - now_done_connect
        needed_connect = max_cur_thread - now_cur_child_thread
        if pending_connect > needed_connect:
            #################################
            ### Too many pending job   ######
            #################################
            time.sleep(new_thread_gap)
        else:
            print("." * 50 + "Main thread! Total:{} Current:{} Failed:{} Submitted: {} Pending: {} Needed:{}".format(
                now_total_connect, now_cur_child_thread, failed_connect, submit_job, pending_connect, needed_connect))

            instance = Client(host, port, ssl_enable)
            instance.start()
            submit_job = submit_job + 1

    end_time = time.asctime(time.localtime(time.time()))
    print("start_time:{}\r\n end_time:{}".format(start_time, end_time))


########## server #######
def server_client(sock, address, client_id):
    recv_len = 0
    while True:
        try:
            data = sock.recv(4096)
            recv_len += len(data)
        except:
            sock.close()
            break
        if recv_len >= server_data_len:
            sock.sendall(str.encode(server_send_message))
            break
    sock.close()


def server_multi_thread_main(host, port):
    total_connections = 0
    print("host:{} port:{}".format(host, port))
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((host, port))
    sock.listen(server_max_cocurrent_thread)
    with ThreadPoolExecutor(max_workers=server_max_cocurrent_thread) as pool:
        while True:
            try:
                new_sock, address = sock.accept()
                new_sock.setsockopt(socket.IPPROTO_TCP,
                                    socket.TCP_MAXSEG, TCP_MSS)
            except Exception as e:
                print("." * 100 + "Accept failed!")
            else:
                total_connections = total_connections + 1
                print("{}:{} New connectoin ID:{} ".format(
                    host, port, total_connections))
                future1 = pool.submit(
                    server_client, new_sock, address, total_connections)


def server_multi_ssl_thread_main(host, port):
    total_connections = 0
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain('/root/devtest_micro-service/sish_root_ca/mycert.pem',
                            '/root/devtest_micro-service/sish_root_ca/mycert.key')
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.bind((host, port))
        sock.listen(server_max_cocurrent_thread)
        with ThreadPoolExecutor(max_workers=server_max_cocurrent_thread) as pool:
            with context.wrap_socket(sock, server_side=True) as ssock:
                while True:
                    try:
                        new_sock, address = ssock.accept()
                        new_sock.setsockopt(
                            socket.IPPROTO_TCP, socket.TCP_MAXSEG, TCP_MSS)
                    except Exception as e:
                        print("." * 100 + "Accept failed!")
                    else:
                        total_connections = total_connections + 1
                        print("{}:{} New connectoin ID:{} ".format(
                            host, port, total_connections))
                        future1 = pool.submit(
                            server_client, new_sock, address, total_connections)


def server_thread_main(host, port, ssl_enable):
    if ssl_enable == True:
        server_multi_ssl_thread_main(host, port)
    else:
        server_multi_thread_main(host, port)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()

    parser.add_argument(
        "--role",
        help="client or server",
        choices=["client", "server"],
        default="client"
    )
    parser.add_argument(
        "--server_ip", help="server ip", default='192.168.10.3'
    )

    parser.add_argument(
        "--server_port", help="server port", default='443'
    )
    parser.add_argument(
        "--ssl", help="ssl enable", action="store_true"
    )

    parser.add_argument(
        "--one_client", help="debug on client by single thread", action="store_true"
    )

    parser.add_argument(
        "--client_sum", help="total client connectoins", default=100
    )

    parser.add_argument(
        "--client_concur", help="client concurrent connectoins", default=10
    )

    args = parser.parse_args()

    role = args.role
    port = int(args.server_port)
    host = args.server_ip

    if args.ssl:
        ssl_enable = True
    else:
        ssl_enable = False

    if args.one_client:
        one_client = True
    else:
        one_client = False

    max_total_connect = int(args.client_sum)
    max_cur_thread = int(args.client_concur)

    client_send_message = 'HEAD / HTTP/1.0\r\nHost: 193.168.10.3\r\nUser-Agent: HTTPing v2.5\r\n\r\n'
    server_send_message = 'HTTP/1.1 200 OK\r\nServer: www.office.com\r\nDate: Fri, 07 Jan 2022 05:43:22 GMT\r\nConnection: close\r\n\r\n'

    server_data_len = len(client_send_message)
    client_data_len = len(server_send_message)

    print("{} {} {} ssl_enable:{}".format(role, host, port, ssl_enable))
    if role == 'client':
        if one_client == True:
            client = Client(host, port, ssl_enable)
            client.start()
        else:

            client_multi_thread_main(host, port, ssl_enable)
    else:
        server_thread_main(host, port, ssl_enable)
