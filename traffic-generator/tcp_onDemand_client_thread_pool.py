import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
import multiprocessing
##### Parameters you can modify ######
host = '193.168.10.3'
port = 8111
role = 'client'
max_total_connect = 10000
max_cocurrent_thread = 900
server_message = "This is server" * 5
client_message = "This is client" * 5
new_thread_gap = 0.0005
new_thread_gap = 0
child_process_num = 2
#####################################
cocurrent_thread_new = max_cocurrent_thread + int(max_cocurrent_thread * 0.1)
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
client_thread_num = 0
failed_connect = 0


def my_client(host, port):
    global total_connect, client_thread_num, failed_connect
    ########################
    # ### Update global value #
    # lock.acquire()
    # client_thread_num = client_thread_num + 1
    # total_connect = total_connect + 1
    # my_id = total_connect
    # print("Child Thread:{} Created! Update Current thread num:{}".format(my_id,
    #                                                                      client_thread_num))
    # lock.release()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
    except:
        # ########################
        # ### Update global value #
        # lock.acquire()
        # client_thread_num = client_thread_num - 1
        # failed_connect = failed_connect + 1
        # lock.release()
        # ########################
        print("*" * 50 + "Exception!! Failed to Connect!")
        return
    ########################
    ### Update global value #
    lock.acquire()
    client_thread_num = client_thread_num + 1
    total_connect = total_connect + 1
    my_id = total_connect
    print("Child :{} Created! Current thread num:{}".format(my_id,
                                                            client_thread_num))
    lock.release()
    # ########################
    try:
        sock.sendall(str.encode(send_message))
    except:
        ########################
        ### Update global value #
        lock.acquire()
        client_thread_num = client_thread_num - 1
        failed_connect = failed_connect + 1
        print("*" * 100 + "Exception!!  Failed to Send! Child Thread:{}".format(my_id, client_thread_num))
        lock.release()
        ########################
        return
    recv_len = 0
    while True:
        try:
            data = sock.recv(4096)
            recv_len += len(data)
        except:
            ########################
            ### Update global value ##
            lock.acquire()
            print("Exception!!Failed to Receive! Child Thread:{}!".format(my_id))
            failed_connect = failed_connect + 1
            client_thread_num = client_thread_num - 1
            lock.release()
            ########################
            return
        if recv_len >= data_len:
            break
    ########################
    ### Update global value ##
    lock.acquire()
    print("Child :{} Finished! Current thread num:{}".format(my_id,
                                                             client_thread_num))
    client_thread_num = client_thread_num - 1
    lock.release()
    ########################
    sock.close()


def multi_thread_main(host, port):
    start_time = time.asctime(time.localtime(time.time()))
    with ThreadPoolExecutor(max_workers=cocurrent_thread_new) as pool:
        submit_job = 0
        while True:
            ########################
            # Update global value
            lock.acquire()
            now_total_connect = total_connect
            now_client_thread_num = client_thread_num
            print("." * 100 + "Main get lock! Total connections:{} Current connections:{} Failed:{} Submit task: {}".format(
                now_total_connect, now_client_thread_num, failed_connect, submit_job))
            lock.release()
            ########################
            if now_client_thread_num < max_cocurrent_thread:
                future1 = pool.submit(my_client, host, port)
                submit_job = submit_job + 1
            else:
                time.sleep(0.01)
            if now_total_connect > max_total_connect:
                break
            time.sleep(new_thread_gap)  # imortant value
    end_time = time.asctime(time.localtime(time.time()))
    print("start_time:{}\r\n end_time:{}".format(start_time, end_time))


def multi_process_main(host, port):
    print("Main Process")
    pool = multiprocessing.Pool(processes=child_process_num)
    for i in range(child_process_num):
        pool.apply_async(multi_thread_main, (host, port + i))

    pool.close()
    pool.join()


multi_thread_main(host, port)
# multi_process_main(host, port)
# my_client()
# 2000 connection/15s    133 connection/s
# 5000 connection/s
