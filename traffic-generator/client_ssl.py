import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor
import multiprocessing

######################################
##### Parameters you can modify ######
######################################
host = '193.168.10.3'
port = 443

max_total_connect = 2000
max_cur_thread = 100

# server_message = "This is server" * 5000
# client_message = "This is client" * 5000

server_message = "This is server" * 5
client_message = "This is client" * 5
client_message = 'HEAD / HTTP/1.0\r\nHost: 193.168.10.3\r\nUser-Agent: HTTPing v2.5\r\n\r\n'
server_message = 'HTTP/1.1 200 OK\r\nServer: www.office.com\r\nDate: Fri, 07 Jan 2022 05:43:22 GMT\r\nConnection: close\r\n\r\n'

new_thread_gap = 0.001
# new_thread_gap = 0

######################################
##  No change below                ###
######################################
role = 'client'
cocurrent_thread_new = max_cur_thread + int(max_cur_thread * 0.1)
client_message_len = len(client_message)
server_message_len = len(server_message)

if role == 'client':
    data_len = server_message_len
    send_message = client_message
else:
    data_len = client_message_len
    send_message = server_message


lock = threading.Lock()
total_connect = 0
cur_child_thread = 0
failed_connect = 0
done_connect = 0

ssl_enable = True


class Client(threading.Thread):

    def run(self):
        global total_connect, cur_child_thread, failed_connect, done_connect
        # try:
        #     sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #     if ssl_enable == True:
        #         ########################
        #         ###Wrap tcp with SSL ###
        #         ########################
        #         context = ssl.create_default_context()
        #         context.load_verify_locations(
        #             "/root/devtest_micro-service/sish_root_ca/mycert.pem")
        #         sock = context.wrap_socket(sock,
        #                                    cert_reqs=ssl.CERT_REQUIRED,
        #                                    server_hostname="www.cisco_test.com")
        #     sock.connect((host, port))
        # except:
        #     print("*" * 20 + "Exception!! Failed to Connect!")
        #     return

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if ssl_enable == True:
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
        lock.acquire()
        cur_child_thread = cur_child_thread + 1
        total_connect = total_connect + 1
        my_id = total_connect
        print("Child :{} Created! Current thread num:{}".format(my_id,
                                                                cur_child_thread))
        lock.release()
        ########################
        ### Send message now   #
        ########################
        try:
            sock.sendall(str.encode(send_message))
        except:
            #####################################
            ### Send failed. Update global value#
            #####################################
            lock.acquire()
            cur_child_thread = cur_child_thread - 1
            failed_connect = failed_connect + 1
            done_connect += 1
            print(
                "*" * 50 + "Exception!!  Failed to Send! Child Thread:{}".format(my_id, cur_child_thread))
            lock.release()
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
                lock.acquire()
                print(
                    "Exception!!Failed to Receive! Child Thread:{}!".format(my_id))
                failed_connect = failed_connect + 1
                cur_child_thread = cur_child_thread - 1
                done_connect += 1
                lock.release()
                return
            if recv_len >= data_len:
                break
        sock.close()
        ################################################
        ### Communication finished. Uodate global value#
        ################################################
        lock.acquire()
        print("Child :{} Finished! Current thread num:{}".format(my_id,
                                                                 cur_child_thread))
        cur_child_thread = cur_child_thread - 1
        done_connect += 1
        lock.release()


def multi_thread_main(host, port):
    global total_connect, cur_child_thread, failed_connect, done_connect
    start_time = time.asctime(time.localtime(time.time()))
    submit_job = 0
    while True:
        ########################
        ### Update global value#
        ########################
        lock.acquire()
        now_total_connect = total_connect
        now_cur_child_thread = cur_child_thread
        now_done_connect = done_connect
        lock.release()
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
            instance = Client()
            instance.start()
            submit_job = submit_job + 1

    end_time = time.asctime(time.localtime(time.time()))
    print("start_time:{}\r\n end_time:{}".format(start_time, end_time))


multi_thread_main(host, port)
# instance = Client()
# instance.start()
