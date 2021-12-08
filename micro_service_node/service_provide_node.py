from nameko.rpc import rpc
# from elasticsearch import Elasticsearch
import pexpect
import time
import sys
import datetime
# from dateutil.parser import parse
# import csv
from elasticsearch import Elasticsearch
from eBPF import attach_bpf
import subprocess

sys.path.append('/root/devtest_micro-service/modules/trex_client')
sys.path.append('/root/devtest_micro-service/modules/trex_client/interactive')
from interactive.trex.astf import trex_astf_client as astf_api


class GreetingService:
    name = "service_on_node_b"

    @rpc
    def hello(self,
              name="shisi"):
        return "Hello, {}! This is service provide node B".format(name)

    @rpc
    def ebpf_inspect(self, during=60):
        print("*" * 10 + "ebpf_inspect during: {}".format(during))
        res = attach_bpf(during=int(during))
        print("*" * 10 + "ebpf_inspect finsihed")
        return res

    @rpc
    def start_scp_copy(self, during=10):
        time_string = time.strftime('%Y%m%d%H%M%S', time.localtime())
        sub_process_res1 = subprocess.Popen('scp root@192.168.10.3:/home/cisco/c8000v-universalk9_serial.17.06.01.0.201.iso /root/devtest_micro-service/' + time_string + '-c8000v-universalk9_serial.17.06.01.0.201.iso',
                                            shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        res = sub_process_res1.stdout.read()
        print("*" * 10 + "scp copy finsihed")
        return True

    @rpc
    def start_onDemand_client(self, during=10):
        res = subprocess.Popen('python /root/devtest_micro-service/tcp_onDemand_client_thread_pool.py ',
                               shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        res = res.stdout.read()
        return True

    @rpc
    def start_client(self, during=10):
        sub_process_res = subprocess.Popen('/home/sish/sdwan-perf/build/sdwan-perf_linux  -role client -server 192.168.10.3  -num 20 -port 80 -size 10 -reqs 1   -duration 10',
                                           shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        res = sub_process_res.stdout.read()
        return True

    @rpc
    def sftp_copy(self, during=10):
        suffix = time.strftime("%Y-%m-%d-%H-%M-%S", time.localtime())
        sub_process_res = subprocess.Popen('scp root@192.168.10.3:/home/cisco/c8000v-universalk9_serial.17.06.01.0.201.iso  /root/image.' + suffix,
                                           shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        res = sub_process_res.stdout.read()
        return True

    @rpc
    def send_cmd_to_server(self, ip=None, username=None, passwd=None, cmd=None):
        ssh_cmd = 'ssh -o StrictHostKeyChecking=no '
        ssh_cmd += '-o UserKnownHostsFile=/dev/null '
        ssh_cmd += '-o ConnectTimeout=20 '
        ssh_cmd += '-o LogLevel=QUIET -l %s ' % username

        child = pexpect.spawn(ssh_cmd + ip)
        child.expect('[p|P]assword:')
        child.sendline(passwd)
        child.expect('#')
        child.sendline(cmd)
        child.expect('#')
        res = child.after
        child.close()
        return res

    @rpc
    def query_index(self,
                    es_ip='*',
                    username='*',
                    passwd='*',
                    index_name='178_netflow_art_s&l&re'):
        es = Elasticsearch([es_ip], http_auth=(username, passwd), timeout=3600)
        body = {
            "query": {"match_all": {}},
            "size": 10000,
        }
        res = es.search(index=index_name, doc_type='_doc', body=body)
        return res['hits']['hits']

if __name__ == '__main__':
    one = GreetingService()
    print(format(one.ebpf_inspect()))
