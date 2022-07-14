#############################################
##### Python3.3 or Python3.9 supported ######
#############################################
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor
import multiprocessing
import os
import sys
import ipaddress


######################################
##### Parameters you can modify ######
######################################
TCP_MSS = 1360
new_thread_gap = 0.001
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
#######
# from OpenSSL import crypto, SSL


# def cert_gen(
#         emailAddress="emailAddress",
#         commonName="commonName",
#         countryName="NT",
#         localityName="localityName",
#         stateOrProvinceName="stateOrProvinceName",
#         organizationName="organizationName",
#         organizationUnitName="organizationUnitName",
#         serialNumber=0,
#         validityStartInSeconds=0,
#         validityEndInSeconds=10 * 365 * 24 * 60 * 60,
#         KEY_FILE="private.key",
#         CERT_FILE="selfsigned.crt"):
#     # can look at generated file using openssl:
#     # openssl x509 -inform pem -in selfsigned.crt -noout -text
#     # create a key pair
#     k = crypto.PKey()
#     k.generate_key(crypto.TYPE_RSA, 4096)
#     # create a self-signed cert
#     cert = crypto.X509()
#     cert.get_subject().C = countryName
#     cert.get_subject().ST = stateOrProvinceName
#     cert.get_subject().L = localityName
#     cert.get_subject().O = organizationName
#     cert.get_subject().OU = organizationUnitName
#     cert.get_subject().CN = commonName
#     cert.get_subject().emailAddress = emailAddress
#     cert.set_serial_number(serialNumber)
#     cert.gmtime_adj_notBefore(0)
#     cert.gmtime_adj_notAfter(validityEndInSeconds)
#     cert.set_issuer(cert.get_subject())
#     cert.set_pubkey(k)
#     cert.sign(k, 'sha512')
#     with open(CERT_FILE, "wt") as f:
#         f.write(crypto.dump_certificate(
#             crypto.FILETYPE_PEM, cert).decode("utf-8"))
#     with open(KEY_FILE, "wt") as f:
# f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8"))

# cert_gen()

########## UDP server and client ######
import socket


def myLog(msg):
    if no_print == False:
        print(msg)
    else:
        pass


def udp_server(host, port):
    myLog("UDP server running")
    udpsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP
    udpsock.bind((host, port))

    while True:
        data, address = udpsock.recvfrom(1024)  # buffer size is 1024 bytes
        myLog("From {} {} :{}".format(address[0], address[1], str(data)))
        udpsock.sendto(data, address)


class UDPClient(threading.Thread):

    def __init__(self, host, port):
        super(UDPClient, self).__init__()
        self.host = host
        self.port = port
        myLog("udp client instance")

    def run(self):
        global total_connect, cur_child_thread, failed_connect, done_connect, c_respond_delay
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP
        ########################
        ### Update global value#
        ########################
        client_lock.acquire()
        cur_child_thread = cur_child_thread + 1
        total_connect = total_connect + 1
        my_id = total_connect
        myLog("Child :{} Created! Current thread num:{}".format(my_id,
                                                                cur_child_thread))
        client_lock.release()
        # import pdb
        # pdb.set_trace()
        for one_round in message_rounds:
            client_send_message = one_round['c'] * message_padding
            client_data_len = one_round['c']
            recv_len = 0
            try:
                ########################
                ### Send message now   #
                ########################
                myLog("Send to {}:{} message:{}".format(
                    self.host, self.port, client_send_message))
                sock.sendto(str.encode(client_send_message),
                            (self.host, self.port))
            except:
                #####################################
                ### Send failed. Update global value#
                #####################################
                client_lock.acquire()
                cur_child_thread = cur_child_thread - 1
                failed_connect = failed_connect + 1
                done_connect += 1
                myLog(
                    "*" * 50 + "Exception!!  Failed to Send! Child Thread:{}".format(my_id, cur_child_thread))
                client_lock.release()
                sock.close()
                return
            while True:
                #########################################
                ### Send ok! Wait message from server   #
                #########################################
                try:
                    data, addr = sock.recvfrom(4096)
                    recv_len += len(data)
                except:
                    ########################################
                    ### Receive failed. Update global value#
                    ########################################
                    client_lock.acquire()
                    myLog(
                        "Exception!!Failed to Receive! Child Thread:{}!".format(my_id))
                    failed_connect = failed_connect + 1
                    cur_child_thread = cur_child_thread - 1
                    done_connect += 1
                    client_lock.release()
                    sock.close()
                    return
                if recv_len >= client_data_len:
                    ########################################
                    # Receive ok!
                    ########################################
                    break
            # Add message response delay if it is needed
            if c_respond_delay != None:
                time.sleep(float(c_respond_delay))
            # go to next round!
        #########################################
        # Communication finished, Close socket!
        #########################################
        sock.close()
        ##########################
        # Update global value
        #########################
        client_lock.acquire()
        myLog("Child :{} Finished! Current thread num:{}".format(my_id,
                                                                 cur_child_thread))
        cur_child_thread = cur_child_thread - 1
        done_connect += 1
        client_lock.release()


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
        if self.ssl_enable == True:
            ########################
            ###Wrap tcp with SSL ###
            ########################

            #########################################
            ###Python SSL lib diff between versions##
            #########################################
            if '3.3.1' in sys.version:
                context = ssl.SSLContext(client_ssl_version)
                context.load_verify_locations(server_cert)
                sock = context.wrap_socket(sock,
                                           server_hostname=server_hostname)
            else:
                context = ssl.create_default_context()
                context.load_verify_locations(server_cert)
                sock = context.wrap_socket(sock,
                                           # cert_reqs=ssl.CERT_REQUIRED,
                                           server_hostname=server_hostname)

        sock.connect((host, port))

        ########################
        ### Update global value#
        ########################
        client_lock.acquire()
        cur_child_thread = cur_child_thread + 1
        total_connect = total_connect + 1
        my_id = total_connect
        myLog("Child :{} Created! Current thread num:{}".format(my_id,
                                                                cur_child_thread))
        client_lock.release()
        for one_round in message_rounds:
            client_send_message = one_round['c'] * message_padding
            client_data_len = one_round['s']
            recv_len = 0
            try:
                ########################
                ### Send message now   #
                ########################
                sock.sendall(str.encode(client_send_message))
            except:
                #####################################
                ### Send failed. Update global value#
                #####################################
                client_lock.acquire()
                cur_child_thread = cur_child_thread - 1
                failed_connect = failed_connect + 1
                done_connect += 1
                myLog(
                    "*" * 50 + "Exception!!  Failed to Send! Child Thread:{}".format(my_id, cur_child_thread))
                client_lock.release()
                sock.close()
                return
            while True:
                #########################################
                ### Send ok! Wait message from server   #
                #########################################
                try:
                    data = sock.recv(4096)
                    recv_len += len(data)
                except:
                    ########################################
                    ### Receive failed. Update global value#
                    ########################################
                    client_lock.acquire()
                    myLog(
                        "Exception!!Failed to Receive! Child Thread:{}!".format(my_id))
                    failed_connect = failed_connect + 1
                    cur_child_thread = cur_child_thread - 1
                    done_connect += 1
                    client_lock.release()
                    sock.close()
                    return
                if recv_len >= client_data_len:
                    ########################################
                    # Receive ok!
                    ########################################
                    break
            # Add message response delay if it is needed
            if c_respond_delay != None:
                time.sleep(float(c_respond_delay))
            # go to next round!
        #########################################
        # Communication finished, Close socket!
        #########################################
        sock.close()
        ##########################
        # Update global value
        #########################
        client_lock.acquire()
        myLog("Child :{} Finished! Current thread num:{}".format(my_id,
                                                                 cur_child_thread))
        cur_child_thread = cur_child_thread - 1
        done_connect += 1
        client_lock.release()


def common_client_multi_thread(host, port, ssl_enable=None, delay=None, client_type='tcp'):
    global total_connect, cur_child_thread, failed_connect, done_connect
    start_time = time.asctime(time.localtime(time.time()))
    submit_job = 0
    base_port = port
    while True:
        #############################################
        # Add delay to control client concurent num
        #############################################
        if delay != None:
            time.sleep(int(delay))
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
            myLog("." * 50 + "Main thread! Total:{} Current:{} Failed:{} Submitted: {} Pending: {} Needed:{}".format(
                now_total_connect, now_cur_child_thread, failed_connect, submit_job, pending_connect, needed_connect))
            if client_type == 'tcp':
                instance = Client(host, port, ssl_enable)
            else:
                instance = UDPClient(host, port)
            instance.start()
            submit_job = submit_job + 1

    end_time = time.asctime(time.localtime(time.time()))
    myLog("start_time:{}\r\n end_time:{}".format(start_time, end_time))


########## server #######
def server_client(sock, address, client_id):
    global s_respond_delay
    for one_round in message_rounds:
        server_send_message = one_round['s'] * message_padding
        server_data_len = one_round['c']
        recv_len = 0
        while True:
            try:
                data = sock.recv(4096)
                recv_len += len(data)
                # print("len:{} ".format(recv_len) + data)
            except:
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
                new_sock.setsockopt(socket.IPPROTO_TCP,
                                    socket.TCP_MAXSEG, TCP_MSS)
            except Exception as e:
                myLog("." * 100 + "Accept failed!")
            else:
                total_connections = total_connections + 1
                myLog("{}:{} New connectoin ID:{} ".format(
                    host, port, total_connections))
                future1 = pool.submit(
                    server_client, new_sock, address, total_connections)


def server_multi_ssl_thread_main(host, port):
    total_connections = 0
    with socket.socket(address_family, socket.SOCK_STREAM, 0) as sock:
        sock.bind((host, port))
        sock.listen(server_max_cocurrent_thread)
        with ThreadPoolExecutor(max_workers=server_max_cocurrent_thread) as pool:

            #####################################
            ### Wrap TCP socket with TLS layer ##
            #####################################
            #########################################
            ###Python SSL lib diff between versions##
            #########################################
            if '3.3.1' in sys.version:
                ssock = ssl.wrap_socket(sock,
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
                    new_sock.setsockopt(
                        socket.IPPROTO_TCP, socket.TCP_MAXSEG, TCP_MSS)
                except Exception as e:
                    myLog("." * 100 + "Accept failed!")
                else:
                    total_connections = total_connections + 1
                    myLog("{}:{} New connectoin ID:{} to {} ".format(
                        host, port, total_connections, address))
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
        default="server"
    )
    parser.add_argument(
        "--server_ip", help="server ip", default=None
    )

    parser.add_argument(
        "--server_port", help="server port", default=443
    )
    parser.add_argument(
        "--ssl", help="ssl enable", action="store_true"
    )

    parser.add_argument(
        "--one_client", help="debug on client by single thread", action="store_true"
    )

    parser.add_argument(
        "--client_sum", help="total client connectoins", default=100000
    )

    parser.add_argument(
        "--client_concur", help="client concurrent connectoins", default=2
    )

    parser.add_argument(
        "--server_name", help="client concurrent connectoins", default='office'
    )

    parser.add_argument(
        "--server", help="client concurrent connectoins", default=None
    )

    parser.add_argument(
        "--client_delay", help="client concurrent control for low speed test", default=1
    )

    parser.add_argument(
        "--ssl_version",
        help="ssl version",
        choices=["2", "3"],
        default="23"
    )
    parser.add_argument(
        "--protocol",
        help="UDP or TCP",
        choices=["udp", "tcp"],
        default="tcp"
    )
    parser.add_argument(
        '--c_mess_lens',
        nargs='+',
        type=int,
    )
    parser.add_argument(
        '--s_mess_lens',
        nargs='+',
        type=int,
    )
    parser.add_argument(
        "--no_print", help="no_print", action="store_true"
    )
    parser.add_argument(
        "--flow_mode",
        help="client or server",
        choices=["asym_s", "asym_c", "sym",
                 "bulksym", "elephant", 'long_live'],
        default="sym"
    )

    parser.add_argument(
        "--s_respond_delay", help="client concurrent connectoins", default=None
    )
    parser.add_argument(
        "--c_respond_delay", help="client concurrent connectoins", default=None
    )

    args = parser.parse_args()

    role = args.role
    protocol = args.protocol
    port = int(args.server_port)
    host = args.server_ip
    if protocol == 'tcp':
        server_name = args.server_name
        server_hostname = 'www.' + server_name + '.com'
        file_path = os.path.dirname(os.path.abspath(__file__))
        server_cert = file_path + '/ca_files/mycert_' + server_name + '.pem'
        server_key = file_path + '/ca_files/mycert_' + server_name + '.key'
    else:
        server_name = None
        server_hostname = None
        server_cert = None
        server_key = None

    if protocol == 'tcp':
        if args.ssl:
            ssl_enable = True
        else:
            ssl_enable = False
    else:
        ssl_enable = False

    if args.no_print:
        no_print = True
    else:
        no_print = False

    if args.one_client:
        one_client = True
    else:
        one_client = False

    if args.server_ip != None:
        if type(ipaddress.ip_network(host)) is ipaddress.IPv4Network:
            address_family = socket.AF_INET
        else:
            address_family = socket.AF_INET6
    else:
        host = args.server

    flow_mode = args.flow_mode

    if int(args.ssl_version) == 2:
        client_ssl_version = ssl.PROTOCOL_SSLv2
    elif int(args.ssl_version) == 3:
        client_ssl_version = ssl.PROTOCOL_SSLv3
    else:
        client_ssl_version = ssl.PROTOCOL_SSLv23

    max_total_connect = int(args.client_sum)
    max_cur_thread = int(args.client_concur)

    client_delay = args.client_delay
    s_respond_delay = args.s_respond_delay
    c_respond_delay = args.c_respond_delay

    client_send_message = 'HEAD / HTTP/1.0\r\nHost: 193.168.10.3\r\nUser-Agent: HTTPing v2.5\r\n\r\n'
    server_send_message = 'HTTP/1.1 200 OK\r\nServer: www.office.com\r\nDate: Fri, 07 Jan 2022 05:43:22 GMT\r\nConnection: close\r\n\r\n'

    server_message_len_list = args.s_mess_lens
    client_message_len_list = args.c_mess_lens

    if server_message_len_list == None and client_message_len_list == None:
        if flow_mode == 'asym_s':
            server_message_len_list = [
                100000, 100000, 100000, 100000, 100000, 100000]
            client_message_len_list = [1, 1, 1, 1, 1, 1]
        elif flow_mode == 'asym_c':
            client_message_len_list = [
                100000, 100000, 100000, 100000, 100000, 100000]
            server_message_len_list = [1, 1, 1, 1, 1, 1]
        elif flow_mode == 'sym':
            server_message_len_list = [1, 1, 1, 1, 1, 1]
            client_message_len_list = [1, 1, 1, 1, 1, 1]
        elif flow_mode == 'bulksym':
            server_message_len_list = [
                100000, 100000, 100000, 100000, 100000, 100000]
            client_message_len_list = [
                100000, 100000, 100000, 100000, 100000, 100000]
        elif flow_mode == 'elephant':
            server_message_len_list = []
            client_message_len_list = []
            for i in range(1000):
                server_message_len_list.append(100000)
                client_message_len_list.append(100000)
        elif flow_mode == 'long_live':
            server_message_len_list = []
            client_message_len_list = []
            for i in range(5):
                server_message_len_list.append(1)
                client_message_len_list.append(1)
            if s_respond_delay is None and c_respond_delay is None:
                s_respond_delay = 60
                c_respond_delay = 60
        else:
            import pdb
            pdb.set_trace()
    if protocol == 'udp':
        server_message_len_list = [1024, 1024]
        client_message_len_list = [1024, 1024]

    assert len(client_message_len_list) == len(server_message_len_list)
    message_rounds = []
    for i in range(len(client_message_len_list)):
        message_rounds.append({'s': server_message_len_list[
                              i], 'c': client_message_len_list[i]})

    print("{} {} {} ssl_enable:{} {}".format(
        role, host, port, ssl_enable, server_hostname))
    print("Traffic mode: {}".format(flow_mode))
    if protocol == 'tcp':
        if role == 'client':
            if one_client == True:
                client = Client(host, port, ssl_enable)
                client.start()
            else:
                common_client_multi_thread(
                    host, port, ssl_enable, client_delay)
        else:
            server_thread_main(host, port, ssl_enable)
    elif protocol == 'udp':
        if role == 'client':
            if one_client == True:
                client = UDPClient(host, port)
                client.start()
            else:
                common_client_multi_thread(
                    host, port, delay=client_delay, client_type='udp')
        else:
            udp_server(host, port)
