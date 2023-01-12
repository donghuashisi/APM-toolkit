# Linux common network tool installed before
# (1)tc （2）ip-netns （3)ip-link  (4)brctl
# Python3 installed
from __future__ import print_function
import os
import yaml
from OpenSSL import crypto
from os.path import join
import random
import re
import time
import concurrent.futures


def create_key_crt(yourName=None, filePath=None):
    if yourName is None:
        yourName = 'www.box.com'

    if filePath is None:
        filePath = '.'

    CN = yourName
    pubkey = "%s.pem" % CN
    privkey = "%s.key" % CN

    pubkey = join(filePath, pubkey)
    privkey = join(filePath, privkey)

    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)
    serialnumber = random.getrandbits(64)

    C = "CN"
    State = "ShangHai"
    City = "ShangHai"
    Organization = "network_test"
    Unit = "test"

    cert = crypto.X509()
    cert.get_subject().C = C
    cert.get_subject().ST = State
    cert.get_subject().L = City
    cert.get_subject().organizationName = Organization
    cert.get_subject().OU = Unit
    cert.get_subject().CN = CN
    cert.set_serial_number(serialnumber)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(31536000)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha512')

    pub = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    priv = crypto.dump_privatekey(crypto.FILETYPE_PEM, k)

    open(pubkey, "wt").write(pub.decode("utf-8"))
    open(privkey, "wt").write(priv.decode("utf-8"))

def mylog(str, logger=None, debug=False):
    if debug:
        if logger is not None:
            logger.info(str)
        else:
            print(str)
    else:
        pass


def call_run(commands, logger=None, debug=None):
    if type(commands) is not list:
        commands = [commands]
    for command in commands:
        mylog(command, logger, debug)
        os.system(command)


def connection_check(ping_cmd, logger=None, debug=None):
    mylog(ping_cmd, logger, debug)
    for i in range(5):
        res = os.popen(ping_cmd).read()
        mylog(res, logger, debug)
        match_res = re.search(r'(\d+) received,', res)
        if match_res is not None and int(match_res.groups()[0]) > 0:
            return True
        time.sleep(1)
    return False


def create_talk_point(pointInfo, logger, debug):
    mylog("." * 10 + "\r\nDeploy Talk Point\r\n" + "." * 10, logger, debug)
    netns_name = pointInfo['netns']
    veth_a = netns_name + "_veth_a"
    veth_b = netns_name + "_veth_b"
    to_bridge = pointInfo['to_bridge']
    cmd_list = [
        "sudo ip netns add {}".format(netns_name),
        "sudo ip netns exec {} ip link set dev lo up ".format(netns_name),
        "sudo ip link add {} type veth peer name {}".format(veth_a, veth_b),
        "sudo ip link set {} netns {}".format(veth_a, netns_name),
        "sudo ip netns exec {} ifconfig {} up".format(netns_name, veth_a),
        "sudo ifconfig {} up".format(veth_b),
        "sudo brctl addif {} {}".format(to_bridge, veth_b),
    ]
    if 'ip' in pointInfo.keys():
        gw = pointInfo['gw']
        ip = pointInfo['ip']
        cmd_list.append("sudo ip -n {} addr add {} dev {}".format(netns_name, ip, veth_a))
        cmd_list.append("sudo ip netns exec {} route add default gw {}".format(netns_name, gw))
        call_run(cmd_list, logger=logger, debug=debug)
        ping_res = connection_check(
            "sudo ip netns exec {} sudo ping -c 5 {} ".format(netns_name, gw), logger=logger, debug=debug
        )
    else:
        gwv6 = pointInfo['gwv6']
        ipv6 = pointInfo['ipv6']
        cmd_list.append("sudo ip netns exec {} ifconfig {} inet6 add {}".format(netns_name, veth_a, ipv6))
        cmd_list.append(
            "sudo ip netns exec {} route -A inet6 add default gw {} dev {}".format(netns_name, gwv6, veth_a)
        )
        call_run(cmd_list, logger=logger, debug=debug)
        ping_res = connection_check(
            "sudo ip netns exec {} sudo ping6 -c 5 {} ".format(netns_name, gwv6), logger=logger, debug=debug
        )

    if 'tc' in pointInfo.keys():
        cmd_list = []
        if 'egress' in pointInfo['tc'].keys():
            cmd = 'sudo ip netns exec {} sudo tc qdisc add dev {} root netem '.format(netns_name, veth_a)
            if 'delay' in pointInfo['tc']['egress'].keys():
                cmd = cmd + " delay {}ms ".format(pointInfo['tc']['egress']['delay'])
                if 'jitter' in pointInfo['tc']['egress'].keys():
                    cmd = cmd + " {}ms ".format(pointInfo['tc']['egress']['jitter'])
            if 'loss' in pointInfo['tc']['egress'].keys() and int(pointInfo['tc']['egress']['loss']) != 0:
                cmd = cmd + " loss {}% ".format(pointInfo['tc']['egress']['loss'])
            cmd_list.append(cmd)
        if 'ingress' in pointInfo['tc'].keys():
            cmd = 'sudo tc qdisc add dev {} root netem '.format(veth_b)
            if 'delay' in pointInfo['tc']['ingress'].keys():
                cmd = cmd + " delay {}ms ".format(pointInfo['tc']['ingress']['delay'])
                if 'jitter' in pointInfo['tc']['ingress'].keys():
                    cmd = cmd + " {}ms ".format(pointInfo['tc']['ingress']['jitter'])
            if 'loss' in pointInfo['tc']['ingress'].keys() and int(pointInfo['tc']['ingress']['loss']) != 0:
                cmd = cmd + " loss {}% ".format(pointInfo['tc']['ingress']['loss'])
            cmd_list.append(cmd)
        call_run(cmd_list, logger=logger, debug=debug)
    if ping_res is False:
        return False
    return True


def deploy_endpoint(endpoint_list=[], mode='concurrent', logger=None, debug=None):
    res = True
    if mode == 'concurrent':
        thread_num = len(endpoint_list)
        with concurrent.futures.ThreadPoolExecutor(max_workers=thread_num) as executor:
            to_do = []
            for i in range(thread_num):
                future = executor.submit(create_talk_point, endpoint_list[i], None, debug)
                to_do.append(future)
            for future in concurrent.futures.as_completed(to_do):
                if future.result() is not True:
                    res = False
    elif mode == 'series':
        for one_point in endpoint_list:
            one_res = create_talk_point(one_point, logger, debug)
            if one_res is not True:
                res = False
    else:
        raise Exception("Wrong Mode")
    return res

class CloudTrafficManager:
    def __init__(self, name=None, logger=None, debug=True, deploy_mode='concurrent'):
        self.name = name
        self.talk_points = []
        file_path = os.path.dirname(os.path.abspath(__file__))
        self.save_file = file_path + '/exist_app_server_client.yaml'
        self.logger = logger
        self.debug = debug
        self.ca_path = file_path + '/app_traffic_tool/ca_files/'
        self.deploy_mode = deploy_mode

    def call_run(self, commands):
        if type(commands) is not list:
            commands = [commands]

        for command in commands:
            mylog(command, self.logger, self.debug)
            os.system(command)

    def store_instance_to_file(self):
        with open(self.save_file, 'w') as file:
            yaml.dump(self.talk_points, file)

    def remove_instance_from_file(self):
        with open(self.save_file) as f:
            content = f.read()
        talk_points = yaml.load(content, Loader=yaml.FullLoader)
        if type(talk_points) is list:
            for talk_point in talk_points:
                mylog("Clean Previous Exiting Instance", self.logger, self.debug)
                self.clear_talk_point(talk_point)
        with open(self.save_file, 'w') as file:
            yaml.dump('', file)

    def stop_traffic(self):
        cmd = 'sudo pkill -f real_app_traffic_tool.py'
        self.call_run(cmd)

    def ca_file_check(self, servers=[]):
        for a_s in servers:
            if 'traffic' in a_s.keys():
                if type(a_s['traffic']) is not list:
                    a_s['traffic'] = [a_s['traffic']]
                for a_traffic in a_s['traffic']:
                    if 'server_name' in a_traffic.keys():
                        s_key_file = self.ca_path + a_traffic['server_name'] + ".key"
                        s_ca_file = self.ca_path + a_traffic['server_name'] + ".pem"
                        if os.path.exists(s_ca_file) is False or os.path.exists(s_key_file) is False:
                            mylog("CA/KEY file not exist.Create new one!", self.logger, self.debug)
                            create_key_crt(a_traffic['server_name'], self.ca_path)

    def parse_dicts(self, server=None, client=None):
        def copy_server_to_client(s_taffic, c_traffic):
            can_copy_keys = ['ssl', 'server_name', 'flow_mode', 'ip', 'server_port', 'flow_db','protocol']
            for a_key in s_taffic.keys():
                if a_key in can_copy_keys:
                    c_traffic[a_key] = s_taffic[a_key]

        if type(server) is dict:
            server = [server]
        if server is None:
            server = []
        self.ca_file_check(server)

        if type(client) is dict:
            client = [client]

        if client is None:
            client = []

        sid = 0
        for a_s in server:
            sid += 1
            a_s['id'] = sid
            a_s['talk_point']['netns'] = 'ns_s' + str(sid)
            if type(a_s['traffic']) is dict:
                a_s['traffic'] = [a_s['traffic']]
            for a_traffic in a_s['traffic']:
                a_traffic['role'] = 'server'

        cid = 0
        for a_c in client:
            cid += 1
            a_c['id'] = cid
            a_c['talk_point']['netns'] = 'ns_c' + str(cid)
            if type(a_c['traffic']) is dict:
                a_c['traffic'] = [a_c['traffic']]

            for a_traffic in a_c['traffic']:
                a_traffic['role'] = 'client'
                if 's_name' in a_traffic.keys():
                    # mylog("Copy Sever Traffic Pattern to Client",
                    #       self.logger, self.debug)
                    find_s = False
                    for a_s in server:
                        if type(a_s['traffic']) is dict:
                            a_s['traffic'] = [a_s['traffic']]
                        for a_s_traffic in a_s['traffic']:
                            if a_s_traffic['name'] == a_traffic['s_name']:
                                find_s = True
                                copy_server_to_client(a_s_traffic, a_traffic)
                    assert find_s is True, "Can't find sever traffic pattern!"
                else:
                    pass
                    # mylog("Client has defined itself traffic pattern",
                    #       self.logger, self.debug)
        return server, client

    def get_endpoint_lists(self, endpoint_list=[]):
        talk_points = []
        for endpoint in endpoint_list:
            if endpoint is not None:
                if type(endpoint) is list:
                    for one_endpoint in endpoint:
                        talk_point = one_endpoint['talk_point']
                        talk_points.append(talk_point)
                elif type(endpoint) is dict:
                    talk_point = endpoint['talk_point']
                    talk_points.append(talk_point)
        return talk_points

    def lanuch_process(self, endpoints=None):
        for endpoint in endpoints:
            if endpoint is not None:
                if type(endpoint) is list:
                    for one_endpoint in endpoint:
                        talk_point = one_endpoint['talk_point']
                        traffic = one_endpoint['traffic']
                        if type(traffic) is list:
                            for one_traffic in traffic:
                                self.app_tool_lanuch(talk_point['netns'], one_traffic)
                        elif type(traffic) is dict:
                            self.app_tool_lanuch(talk_point['netns'], traffic)

                elif type(endpoint) is dict:
                    talk_point = endpoint['talk_point']
                    traffic = endpoint['traffic']
                    if type(traffic) is list:
                        for one_traffic in traffic:
                            self.app_tool_lanuch(talk_point['netns'], one_traffic)
                    elif type(traffic) is dict:
                        self.app_tool_lanuch(talk_point['netns'], traffic)

    def start_traffic(self, name=None, server=None, client=None):
        send_ok = True
        self.clean_history()
        self.parse_dicts(server, client)
        endpoint_list = self.get_endpoint_lists(endpoint_list=[server, client])
        res = deploy_endpoint(endpoint_list, self.deploy_mode, self.logger, self.debug)
        for pointInfo in endpoint_list:
            self.talk_points.append(pointInfo)
        if res is False:
            send_ok = False
        # self.lanuch_process([server])
        # time.sleep(0.5)
        # self.lanuch_process([client])
        for endpoint in [server, client]:
            if endpoint is not None:
                if type(endpoint) is list:
                    for one_endpoint in endpoint:
                        talk_point = one_endpoint['talk_point']
                        traffic = one_endpoint['traffic']
                        if type(traffic) is list:
                            for one_traffic in traffic:
                                self.app_tool_lanuch(talk_point['netns'], one_traffic)
                        elif type(traffic) is dict:
                            self.app_tool_lanuch(talk_point['netns'], traffic)

                elif type(endpoint) is dict:
                    talk_point = endpoint['talk_point']
                    traffic = endpoint['traffic']
                    if type(traffic) is list:
                        for one_traffic in traffic:
                            self.app_tool_lanuch(talk_point['netns'], one_traffic)
                    elif type(traffic) is dict:
                        self.app_tool_lanuch(talk_point['netns'], traffic)
        if send_ok is True:
            return [True, "App traffic send successfully"]
        else:
            return [False, "App traffic send failed"]

    def clear_all_talk_points(self):
        for pointInfo in self.talk_points:
            self.clear_talk_point(pointInfo)
        with open(self.save_file, 'w') as file:
            yaml.dump('', file)
        # self.remove_instance_from_file()
        self.talk_points = []

    def clear_talk_point(self, pointInfo):
        netns_name = pointInfo['netns']
        veth_a = netns_name + "_veth_a"
        veth_b = netns_name + "_veth_b"
        to_bridge = pointInfo['to_bridge']
        if 'tc' in pointInfo.keys():
            cmd_list = [
                'sudo ip netns exec {} tc qdisc del dev {} root'.format(netns_name, veth_a),
                'sudo tc qdisc del dev {} root'.format(veth_b),
            ]
            self.call_run(cmd_list)

        cmd_list = [
            "sudo ip netns exec {} ifconfig {} down".format(netns_name, veth_a),
            "sudo ifconfig {} down".format(veth_b),
            "sudo brctl delif {} {}".format(to_bridge, veth_b),
            "sudo ip netns exec {} ip link delete {} ".format(netns_name, veth_a),
            "sudo ip link del {}".format(veth_b),
            "sudo ip netns del {}".format(netns_name),
        ]
        self.call_run(cmd_list)

    def app_tool_lanuch(self, pointNetNs=None, trafficInfo={}):
        current_path = os.path.abspath(__file__)
        app_tool_path = os.path.abspath(os.path.dirname(current_path) + os.path.sep + ".") + "/app_traffic_tool/"

        cmd = 'python3 ' + app_tool_path + 'real_app_traffic_tool.py'
        if pointNetNs is not None:
            cmd = "sudo ip netns exec {} ".format(pointNetNs) + cmd
        else:
            cmd = "sudo {} ".format(pointNetNs) + cmd

        cmd = cmd + " --role {}".format(trafficInfo['role'])
        if 'ip' in trafficInfo.keys():
            cmd = cmd + " --server_ip {} ".format(trafficInfo['ip'])
        else:
            cmd = cmd + " --server_ip {} ".format(trafficInfo['ipv6'])
        if 'ssl' in trafficInfo.keys() and trafficInfo['ssl'] is True:
            cmd = cmd + " --ssl "
        if 'server_name' in trafficInfo.keys():
            cmd = cmd + " --server_name {} ".format(trafficInfo['server_name'])

        if 'flow_mode' in trafficInfo.keys():
            cmd = cmd + " --flow_mode {} ".format(trafficInfo['flow_mode'])
        
        if 'protocol' in trafficInfo.keys():
            cmd = cmd + " --protocol {} ".format(trafficInfo['protocol'])
        
        if 'one_client' in trafficInfo.keys():
            cmd = cmd + " --one_client "

        if 'client_sum' in trafficInfo.keys():
            cmd = cmd + " --client_sum {} ".format(trafficInfo['client_sum'])

        if 'client_concur' in trafficInfo.keys():
            cmd = cmd + " --client_concur {} ".format(trafficInfo['client_concur'])

        if 'client_delay' in trafficInfo.keys():
            cmd = cmd + " --client_delay {} ".format(trafficInfo['client_delay'])

        if 'client_cps' in trafficInfo.keys():
            cmd = cmd + " --client_cps {} ".format(trafficInfo['client_cps'])

        if 'server_port' in trafficInfo.keys():
            cmd = cmd + " --server_port {} ".format(trafficInfo['server_port'])

        if 'c_mess_lens' in trafficInfo.keys():
            cmd = cmd + " --c_mess_lens {} ".format(trafficInfo['c_mess_lens'])

        if 's_mess_lens' in trafficInfo.keys():
            cmd = cmd + " --s_mess_lens {} ".format(trafficInfo['s_mess_lens'])

        if 'one_client' in trafficInfo.keys():
            cmd = cmd + " --one_client"

        if 'no_print' in trafficInfo.keys():
            cmd = cmd + " --no_print  "

        if 'flow_db' in trafficInfo.keys():
            cmd = cmd + " --flow_db {} ".format(trafficInfo['flow_db'])

        cmd = cmd + "&"
        mylog("." * 10 + "\r\nDeploy Server/Client\r\n" + "." * 10, self.logger, self.debug)
        self.call_run(cmd)

    def deploy_from_yaml(self, yamlFile, profileName=None):
        with open(yamlFile) as f:
            content = f.read()
        profile_dicts = yaml.load(content, Loader=yaml.FullLoader)

        if profileName is not None:
            servers = profile_dicts[profileName]['servers']
            clients = profile_dicts[profileName]['clients']
        else:
            servers = profile_dicts['servers']
            clients = profile_dicts['clients']
        return self.start_traffic(server=servers, client=clients)

    def clear_all(self):
        self.stop_traffic()
        self.clear_all_talk_points()

    def clean_history(self):
        self.stop_traffic()
        self.remove_instance_from_file()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()

    parser.add_argument("--yaml", help="input traffic file location", default=None)
    parser.add_argument("--case", help="active case in profile", default=None)
    parser.add_argument("--action", help="del or add", choices=["del", "add"], default="add")
    parser.add_argument(
        "--deploy_mode", help="concurrent or series", choices=["concurrent", "series"], default="concurrent"
    )
    args = parser.parse_args()

    profileName = args.case
    traffic_file = args.yaml
    action = args.action
    deploy_mode = args.deploy_mode

    if traffic_file is None:
        traffic_file = "/tmp/app_server_client.yaml"

    myinstance = CloudTrafficManager(deploy_mode=deploy_mode)
    if action == "del":
        myinstance.clean_history()
    else:
        myinstance.deploy_from_yaml(traffic_file, profileName=profileName)
        print("Enter C to clean all traffic!")
        import pdb

        pdb.set_trace()
        myinstance.clear_all()
