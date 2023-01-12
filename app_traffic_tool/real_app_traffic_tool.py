# Only Python3 supported.
# All module here is Python3 Standard Library
# 3rd party module add in this module is not allowed
# https://docs.python.org/3.6/library/index.html
from __future__ import print_function
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor
import os
import sys
import ipaddress
import json


TCP_MSS = 1360
new_thread_gap = 0.005
client_lock = threading.Lock()
total_connect = 0
cur_child_thread = 0
failed_connect = 0
done_connect = 0

server_max_cocurrent_thread = 1000
address_family = socket.AF_INET
message_rounds = []
message_padding = '+'
no_print = False
s_respond_delay = None
c_respond_delay = None

current_path = os.path.dirname(os.path.abspath(__file__))

ca_file_path = current_path + "/ca_files/"

flow_pattern_db = {
    'baseHttp': {
        'payload': 'plain_text',
        'client': ['HEAD / HTTP/1.0\r\nHost: 193.168.10.3\r\nUser-Agent: HTTPing v2.5\r\n\r\n'],
        'server': [
            'HTTP/1.1 200 OK\r\nServer: www.office.com\r\nDate: Fri, 07 Jan 2022 05:43:22 GMT\r\nConnection: close\r\n\r\n'
        ],
    },
    'asym_s': {
        'payload': 'len_list',
        'client': [1, 1, 1, 1, 1, 1],
        'server': [100000, 100000, 100000, 100000, 100000, 100000],
    },
    'asym_c': {
        'payload': 'len_list',
        'client': [100000, 100000, 100000, 100000, 100000, 100000],
        'server': [1, 1, 1, 1, 1, 1],
    },
    'sym': {
        'payload': 'len_list',
        'client': [500, 500, 500, 500, 500, 500, 500, 500, 500, 500, 500, 500],
        'server': [500, 500, 500, 500, 500, 500, 500, 500, 500, 500, 500, 500],
    },
    'bulksym': {
        'payload': 'len_list',
        'client': [100000, 100000, 100000, 100000, 100000, 100000],
        'server': [100000, 100000, 100000, 100000, 100000, 100000],
    },
    'mouse': {
        'payload': 'len_list',
        'client': [1],
        'server': [1],
    },
    'elephant': {
        'payload': 'len_list',
        'client': {
            'num': 100000,
            'message_len': 1,
        },
        'server': {
            'num': 100000,
            'message_len': 100000,
        },
    },
    'long_live': {
        'payload': 'len_list',
        's_respond_delay': 60,
        'c_respond_delay': 60,
        'client': {
            'num': 100000,
            'message_len': 1,
        },
        'server': {
            'num': 100000,
            'message_len': 1,
        },
    },
    'udp_test': {
        'payload': 'plain_text',
        'client': ['request_string'],
        'server': ['response_string'],
    },
}


def myLog(msg):
    if no_print is False:
        print(msg)
    else:
        pass


def udp_server(host, port):
    message = str.encode(message_rounds[0]['s'])
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    while True:
        data, addr = sock.recvfrom(1024)
        myLog("{} {}".format(data, addr))
        sock.sendto(message, addr)


def udp_client(host, port):
    message = str.encode(message_rounds[0]['c'])
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(message, (host, port))
    data, addr = sock.recvfrom(1024)
    myLog("{} {}".format(data, addr))
    sock.close()


class UDPClient_alone(threading.Thread):
    def __init__(self, host, port, my_id=1):
        super(UDPClient_alone, self).__init__()
        self.host = host
        self.port = port
        self.my_id = my_id

    def run(self):
        host = self.host
        port = self.port
        my_id = self.my_id
        myLog("Child :{} Created!".format(my_id))
        message = str.encode(message_rounds[0]['c'])
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(message, (host, port))
        data, addr = sock.recvfrom(1024)
        myLog("{} {}".format(data, addr))
        sock.close()
        myLog("Child :{} Finished!".format(my_id))


class Client_alone(threading.Thread):
    def __init__(self, host, port, my_id, ssl_enable=False):
        super(Client_alone, self).__init__()
        self.host = host
        self.port = port
        self.ssl_enable = ssl_enable
        self.my_id = my_id

    def run(self):
        host = self.host
        port = self.port
        my_id = self.my_id

        sock = socket.socket(address_family, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, TCP_MSS)
        if self.ssl_enable is True:
            # Wrap tcp with SSL
            # Python SSL lib diff between versions
            if '3.3.1' in sys.version:
                context = ssl.SSLContext(client_ssl_version)
                context.load_verify_locations(server_cert)
                sock = context.wrap_socket(sock, server_hostname=server_name)
            else:
                context = ssl.create_default_context()
                context.load_verify_locations(server_cert)
                sock = context.wrap_socket(
                    sock,
                    # cert_reqs=ssl.CERT_REQUIRED,
                    server_hostname=server_name,
                )
        try:
            sock.connect((host, port))
        except Exception as e:
            myLog("*" * 50 + "Exception!! Failed to create TCP {}".format(e))
            return

        # Update global value
        myLog("Child :{} Created!".format(my_id))

        for one_round in message_rounds:
            client_send_message = one_round['c']
            client_data_len = len(one_round['s'])
            recv_len = 0
            try:
                # Send message now
                sock.sendall(str.encode(client_send_message))
            except Exception as e:
                # Send failed. Update global value
                myLog("*" * 50 + "Exception!!  Failed to Send! Child Thread:{}".format(my_id))
                myLog("{}".format(e))
                sock.close()
                return
            while True:
                # Send ok! Wait message from server
                try:
                    data = sock.recv(4096)
                    # print(data)
                    recv_len += len(data)
                except Exception as e:
                    # Receive failed. Update global value
                    myLog("{}".format(e))
                    myLog("Exception!!Failed to Receive! Child Thread:{}!".format(my_id))
                    sock.close()
                    return
                if recv_len >= client_data_len:
                    # Receive ok!
                    break
            # Add message response delay if it is needed
            if c_respond_delay is not None:
                time.sleep(float(c_respond_delay))
            # go to next round!
        # Communication finished, Close socket!
        sock.close()
        # Update global value
        myLog("Child :{} Finished!".format(my_id))


class Client(threading.Thread):
    def __init__(self, host, port, ssl_enable=False):
        super(Client, self).__init__()
        self.host = host
        self.port = port
        self.ssl_enable = ssl_enable

    def run(self):
        global total_connect, cur_child_thread, failed_connect, done_connect, c_respond_delay
        host = self.host
        port = self.port

        sock = socket.socket(address_family, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, TCP_MSS)
        if self.ssl_enable is True:
            # Wrap tcp with SSL
            # Python SSL lib diff between versions
            if '3.3.1' in sys.version:
                context = ssl.SSLContext(client_ssl_version)
                context.load_verify_locations(server_cert)
                sock = context.wrap_socket(sock, server_hostname=server_name)
            else:
                context = ssl.create_default_context()
                context.load_verify_locations(server_cert)
                sock = context.wrap_socket(
                    sock,
                    # cert_reqs=ssl.CERT_REQUIRED,
                    server_hostname=server_name,
                )
        try:
            sock.connect((host, port))
        except Exception as e:
            myLog("*" * 50 + "Exception!! Failed to create TCP {}".format(e))
            return

        # Update global value
        client_lock.acquire()
        cur_child_thread = cur_child_thread + 1
        total_connect = total_connect + 1
        my_id = total_connect
        myLog("Child :{} Created! Current thread num:{}".format(my_id, cur_child_thread))
        client_lock.release()

        for one_round in message_rounds:
            client_send_message = one_round['c']
            client_data_len = len(one_round['s'])
            recv_len = 0
            try:
                # Send message now
                sock.sendall(str.encode(client_send_message))
            except Exception as e:
                # Send failed. Update global value
                client_lock.acquire()
                cur_child_thread = cur_child_thread - 1
                failed_connect = failed_connect + 1
                done_connect += 1
                myLog("*" * 50 + "Exception!!  Failed to Send! Child Thread:{}".format(my_id))
                myLog("{}".format(e))
                client_lock.release()
                sock.close()
                return
            while True:
                # Send ok! Wait message from server
                try:
                    data = sock.recv(4096)
                    # print(data)
                    recv_len += len(data)
                except Exception as e:
                    # Receive failed. Update global value
                    client_lock.acquire()
                    myLog("{}".format(e))
                    myLog("Exception!!Failed to Receive! Child Thread:{}!".format(my_id))
                    failed_connect = failed_connect + 1
                    cur_child_thread = cur_child_thread - 1
                    done_connect += 1
                    client_lock.release()
                    sock.close()
                    return
                if recv_len >= client_data_len:
                    # Receive ok!
                    break
            # Add message response delay if it is needed
            if c_respond_delay is not None:
                time.sleep(float(c_respond_delay))
            # go to next round!
        # Communication finished, Close socket!
        sock.close()
        # Update global value
        client_lock.acquire()
        myLog("Child :{} Finished! Current thread num:{}".format(my_id, cur_child_thread))
        cur_child_thread = cur_child_thread - 1
        done_connect += 1
        client_lock.release()


def client_multi_thread_main(host, port, ssl_enable, delay=None):
    global total_connect, cur_child_thread, failed_connect, done_connect
    start_time = time.asctime(time.localtime(time.time()))
    submit_job = 0
    while True:
        # Add delay to control client concurent num
        if delay is not None:
            time.sleep(float(delay))
        # Update global value
        client_lock.acquire()
        now_done_connect = done_connect
        now_total_connect = total_connect
        now_cur_child_thread = cur_child_thread
        client_lock.release()
        if now_total_connect > max_total_connect:
            # Total connection finished
            break
        # New job submit
        if now_cur_child_thread >= max_cur_thread:
            # co-current reach max
            time.sleep(new_thread_gap)
            continue
        # co-current < max
        # running_connect = submit_job - now_done_connect
        running_connect = now_total_connect - now_done_connect
        needed_connect = max_cur_thread - now_cur_child_thread

        if running_connect > needed_connect:
            # Too many pending job
            time.sleep(new_thread_gap)
        else:
            myLog(
                "." * 50
                + "Main thread! Total:{} Current:{} Failed:{} Submitted: {} Pending: {} Needed:{}".format(
                    now_total_connect, now_cur_child_thread, failed_connect, submit_job, running_connect, needed_connect
                )
            )
            instance = Client(host, port, ssl_enable)
            instance.start()
            submit_job = submit_job + 1

    end_time = time.asctime(time.localtime(time.time()))
    myLog("start_time:{}\r\n end_time:{}".format(start_time, end_time))


def client_multi_thread_cps(host, port, ssl_enable, cps=1):
    global total_connect, max_total_connect
    start_time = time.asctime(time.localtime(time.time()))
    client_threads = []
    while True:
        if total_connect >= max_total_connect:
            break
        total_connect += 1
        myLog("." * 50 + "Main thread! Total:{}".format(total_connect))
        instance = Client_alone(host, port, total_connect, ssl_enable)
        client_threads.append(instance)
        instance.start()
        time.sleep(float(1.0 / cps))
    for t in client_threads:
        t.join()
    end_time = time.asctime(time.localtime(time.time()))
    myLog("start_time:{}\r\n end_time:{}".format(start_time, end_time))


def udp_client_multi_thread_cps(host, port, cps=1):
    global total_connect, max_total_connect
    start_time = time.asctime(time.localtime(time.time()))
    client_threads = []
    while True:
        if total_connect >= max_total_connect:
            break
        total_connect += 1
        myLog("." * 50 + "Main thread! Total:{}".format(total_connect))
        instance = UDPClient_alone(host, port, total_connect)
        client_threads.append(instance)
        instance.start()
        time.sleep(float(1.0 / cps))
    for t in client_threads:
        t.join()
    end_time = time.asctime(time.localtime(time.time()))
    myLog("start_time:{}\r\n end_time:{}".format(start_time, end_time))
# server
def server_client(sock, address, client_id):
    global s_respond_delay
    for one_round in message_rounds:
        server_send_message = one_round['s']
        server_data_len = len(one_round['c'])
        recv_len = 0
        while True:
            try:
                data = sock.recv(4096)
                recv_len += len(data)
                # print("len:{} ".format(recv_len) + data)
            except Exception as e:
                myLog("{}".format(e))
                sock.close()
                return
                # break
            if len(data) == 0:
                sock.close()
                return
            myLog("From {} :".format(address) + str(data))
            # if str(data) == "b\'\'":
            #     sock.close()
            #     return
            if recv_len >= server_data_len:
                break
        # Add message response delay if it is needed
        if s_respond_delay is not None:
            time.sleep(float(s_respond_delay))
        sock.sendall(str.encode(server_send_message))
    sock.close()


def server_multi_thread_main(host, port):
    total_connections = 0
    myLog("host:{} port:{}".format(host, port))
    sock = socket.socket(address_family, socket.SOCK_STREAM)
    sock.bind((host, port))
    sock.listen(server_max_cocurrent_thread)
    with ThreadPoolExecutor(max_workers=server_max_cocurrent_thread) as pool:
        while True:
            try:
                new_sock, address = sock.accept()
                new_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, TCP_MSS)
            except Exception as e:
                myLog("." * 100 + "Accept failed!")
                myLog("{}".format(e))
            else:
                total_connections = total_connections + 1
                myLog("{}:{} New connectoin ID:{} ".format(host, port, total_connections))
                pool.submit(server_client, new_sock, address, total_connections)


def server_multi_ssl_thread_main(host, port):
    total_connections = 0
    with socket.socket(address_family, socket.SOCK_STREAM, 0) as sock:
        sock.bind((host, port))
        sock.listen(server_max_cocurrent_thread)
        with ThreadPoolExecutor(max_workers=server_max_cocurrent_thread) as pool:
            # Wrap TCP socket with TLS layer
            # Python SSL lib diff between versions
            if '3.3.1' in sys.version:
                ssock = ssl.wrap_socket(
                    sock,
                    keyfile=server_key,
                    certfile=server_cert,
                    server_side=True,
                    # cert_reqs=CERT_NONE,
                    # ssl_version=PROTOCOL_SSLv23,
                    # ca_certs=None,
                    # do_handshake_on_connect=True,
                    # suppress_ragged_eofs=True,
                    # ciphers=None
                )
            else:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(server_cert, server_key)
                ssock = context.wrap_socket(sock, server_side=True)
            while True:
                try:
                    new_sock, address = ssock.accept()
                    new_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, TCP_MSS)
                except Exception as e:
                    myLog("." * 100 + "Accept failed!")
                    myLog("{}".format(e))
                else:
                    total_connections = total_connections + 1
                    myLog("{}:{} New connectoin ID:{} to {} ".format(host, port, total_connections, address))
                    pool.submit(server_client, new_sock, address, total_connections)


def server_thread_main(host, port, ssl_enable):
    if ssl_enable is True:
        server_multi_ssl_thread_main(host, port)
    else:
        server_multi_thread_main(host, port)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()

    parser.add_argument("--role", help="client or server", choices=["client", "server"], default="server")
    parser.add_argument("--server_ip", help="server ip", default=None)

    parser.add_argument("--server_port", help="server port", default=443)
    parser.add_argument("--ssl", help="ssl enable", action="store_true")

    parser.add_argument("--one_client", help="debug one client with no thread", action="store_true")

    parser.add_argument("--client_sum", help="total client connectoins", default=100000)

    parser.add_argument("--client_concur", help="client concurrent connectoins", default=2)

    parser.add_argument("--client_cps", help="client connection per second", default=None)

    parser.add_argument("--server_name", help="server name in CA", default=None)

    parser.add_argument("--server", help="domain name of server", default=None)

    parser.add_argument("--client_delay", help="client concurrent control for low speed test", default=0.005)

    parser.add_argument("--ssl_version", help="ssl version", choices=["2", "3"], default="23")

    # parser.add_argument(
    #     '--c_mess_lens',
    #     nargs='+',
    #     type=int,
    # )
    # parser.add_argument(
    #     '--s_mess_lens',
    #     nargs='+',
    #     type=int,
    # )
    parser.add_argument(
        "--flow_db",
        help="input a flow pattern db source. If None, use builtin DB",
        default=None,
    )
    parser.add_argument("--no_print", help="no_print", action="store_true")
    parser.add_argument(
        "--flow_mode",
        help="client or server",
        # choices=["asym_s", "asym_c", "sym", "bulksym", "elephant", 'long_live', 'mouse'],
        default=None,
    )

    parser.add_argument("--s_respond_delay", help="client concurrent connectoins", default=None)
    parser.add_argument("--c_respond_delay", help="client concurrent connectoins", default=None)

    parser.add_argument("--protocol", help="tcp or udp", choices=["tcp", "udp"], default="tcp")

    args = parser.parse_args()
    protocol = args.protocol
    # Basic Server/Client IP/Port
    role = args.role
    port = int(args.server_port)
    if args.server_ip is not None:
        host = args.server_ip
        if type(ipaddress.ip_network(host)) is ipaddress.IPv4Network:
            address_family = socket.AF_INET
        else:
            address_family = socket.AF_INET6
    else:
        assert role == 'client', "Sever can't use a domain name to bind socket"
        host = args.server
    # End

    # ssl section
    if args.ssl:
        ssl_enable = True
    else:
        ssl_enable = False

    server_name = args.server_name
    if ssl_enable is True:
        server_cert = None
        server_key = None
        if server_name is not None:
            server_cert = ca_file_path + server_name + '.pem'
            server_key = ca_file_path + server_name + '.key'
            if os.path.exists(server_cert) is False or os.path.exists(server_key) is False:
                print("No existing cer and key file exist! You use ca.py to generate!")
                print("CA:{}  Key:{}".format(server_cert, server_key))
                sys.exit(0)
        if int(args.ssl_version) == 2:
            client_ssl_version = ssl.PROTOCOL_SSLv2
        elif int(args.ssl_version) == 3:
            client_ssl_version = ssl.PROTOCOL_SSLv3
        else:
            client_ssl_version = ssl.PROTOCOL_SSLv23
    # End

    if args.no_print:
        no_print = True
    else:
        no_print = False

    # Flow Pattern Definition
    flow_db = args.flow_db
    if flow_db is not None:
        flow_db = current_path + "/flow_db/" + flow_db
        with open(flow_db, 'r') as f:
            config = f.read()
        flow_pattern_db = json.loads(config)

    flow_mode = args.flow_mode
    if flow_mode is None:
        if args.flow_db is None:
            flow_mode = 'baseHttp'
        else:
            raise Exception("You need input a flow pattern")

    manipulate = False
    tracstion_round = 0
    get_pattern = flow_pattern_db[flow_mode]
    if type(get_pattern['client']) is list:
        c_len = len(get_pattern['client'])
        s_len = len(get_pattern['server'])
        tracstion_round = s_len
        assert c_len == s_len, "Flow Pattern You chosed is Wrong!"
    elif type(get_pattern['client']) is dict:
        manipulate = True
        c_len = get_pattern['client']['num']
        s_len = get_pattern['server']['num']
        assert c_len == s_len, "Flow Pattern You chosed is Wrong!"
        tracstion_round = s_len

    message_rounds = []
    for i in range(tracstion_round):
        if get_pattern['payload'] == 'plain_text':
            s_payload = get_pattern['server'][i]
            c_payload = get_pattern['client'][i]
        elif get_pattern['payload'] == 'len_list':
            if manipulate is True:
                s_payload = get_pattern['server']['message_len'] * message_padding
                c_payload = get_pattern['client']['message_len'] * message_padding
            else:
                s_payload = get_pattern['server'][i] * message_padding
                c_payload = get_pattern['client'][i] * message_padding
        message_rounds.append({'s': s_payload, 'c': c_payload})
    if 's_respond_delay' in get_pattern.keys():
        s_respond_delay = get_pattern['s_respond_delay']
    if 'c_respond_delay' in get_pattern.keys():
        c_respond_delay = get_pattern['c_respond_delay']

    if args.s_respond_delay is not None:
        s_respond_delay = args.s_respond_delay
    if args.c_respond_delay is not None:
        c_respond_delay = args.c_respond_delay
    # End

    # Client Connection Per Second
    if args.one_client:
        one_client = True
    else:
        one_client = False
    max_total_connect = int(args.client_sum)
    max_cur_thread = int(args.client_concur)
    client_delay = args.client_delay
    client_cps = None
    if args.client_cps:
        client_cps = int(args.client_cps)
    # End
    if protocol == 'tcp':
        print(("{} {} {} ssl_enable:{} {}".format(role, host, port, ssl_enable, server_name)))
        if role == 'client':
            if one_client is True:
                client = Client(host, port, ssl_enable)
                client.start()
            elif client_cps is not None:
                client_multi_thread_cps(host, port, ssl_enable, client_cps)
            else:
                client_multi_thread_main(host, port, ssl_enable, client_delay)
        else:
            server_thread_main(host, port, ssl_enable)
    elif protocol == 'udp':
        if len(message_rounds) > 1:
            print("UDP communication support one message round only")
            sys.exit(0)
        if role == 'client':
            # udp_client(host,port)
            if one_client is True:
                client = UDPClient_alone(host, port)
                client.start()
                # udp_client(host,port)
            elif client_cps is not None:
                udp_client_multi_thread_cps(host, port, client_cps)
        else:
            udp_server(host, port)
