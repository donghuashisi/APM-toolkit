import os
import time
import subprocess


class CloudTrafficEngine:

    def __init__(self, name=None):
        self.name = name
        self.talk_points = []
        self.alive_process = []

    def call_run(self, commands):
        if type(commands) is not list:
            commands = [commands]

        for command in commands:
            print(command)
            os.system(command)

    def stop_traffic(self):
        cmd = 'sudo pkill -f real_app_traffic_tool.py'
        self.call_run(cmd)
        # for child in self.alive_process:
        #     child.kill()

    def start_traffic(self, name=None, server={}, client={}):
        if server != {}:
            server_point = server['talk_point']
            server_traffic = server['traffic']
            self.create_talk_point(server_point)
            self.app_tool_lanuch(server_point['netns'], server_traffic)
        if client != {}:
            client_point = client['talk_point']
            client_traffic = client['traffic']
            self.create_talk_point(client_point)
            self.app_tool_lanuch(client_point['netns'], client_traffic)

    def clear_all_talk_points(self):
        for pointInfo in self.talk_points:
            self.clear_talk_point(pointInfo)

    def clear_talk_point(self, pointInfo):
        netns_name = pointInfo['netns']
        veth_a = netns_name + "_veth_a"
        veth_b = netns_name + "_veth_b"
        to_bridge = pointInfo['to_bridge']
        if 'tc' in pointInfo.keys():
            cmd_list = [
                'sudo ip netns exec {} tc qdisc del dev {} root'.format(
                    netns_name, veth_a),
                'sudo tc qdisc del dev {} root'.format(veth_b),
            ]
            self.call_run(cmd_list)

        cmd_list = [
            "sudo ip netns exec {} ifconfig {} down".format(
                netns_name, veth_a),
            "sudo ifconfig {} down".format(veth_b),
            "sudo brctl delif {} {}".format(to_bridge, veth_b),
            "sudo ip netns exec {} ip link delete {} ".format(
                netns_name, veth_a),
            "sudo ip link del {}".format(veth_b),
            "sudo ip netns del {}".format(netns_name),
        ]
        self.call_run(cmd_list)

    def app_tool_lanuch(self, pointNetNs=None, trafficInfo={}):
        current_path = os.path.abspath(__file__)
        app_tool_path = os.path.abspath(os.path.dirname(
            current_path) + os.path.sep + ".") + "/app_traffic_tool/"

        cmd = 'python3 ' + app_tool_path + 'real_app_traffic_tool.py'
        if pointNetNs is not None:
            cmd = "sudo ip netns exec {} ".format(pointNetNs) + cmd
        else:
            cmd = "sudo ".format(pointNetNs) + cmd

        cmd = cmd + " --role {}".format(trafficInfo['role'])
        cmd = cmd + " --server_ip {} ".format(trafficInfo['ip'])
        if 'ssl' in trafficInfo.keys() and trafficInfo['ssl'] == True:
            cmd = cmd + " --ssl "
        if 'server_name'in trafficInfo.keys():
            cmd = cmd + " --server_name {} ".format(trafficInfo['server_name'])

        if 'flow_mode'in trafficInfo.keys():
            cmd = cmd + " --flow_mode {} ".format(trafficInfo['flow_mode'])

        if 'one_client'in trafficInfo.keys():
            cmd = cmd + " --one_client "

        if 'client_sum'in trafficInfo.keys():
            cmd = cmd + " --client_sum {} ".format(trafficInfo['client_sum'])

        if 'client_concur'in trafficInfo.keys():
            cmd = cmd + \
                " --client_concur {} ".format(trafficInfo['client_concur'])

        if 'client_delay'in trafficInfo.keys():
            cmd = cmd + \
                " --client_delay {} ".format(trafficInfo['client_delay'])

        if 'no_print'in trafficInfo.keys():
            cmd = cmd + " --no_print  "

        cmd = cmd + "&"
        self.call_run(cmd)
        # proc = subprocess.Popen(cmd, shell=True)
        # self.alive_process.append(proc)

    def create_talk_point(self, pointInfo):
        netns_name = pointInfo['netns']
        veth_a = netns_name + "_veth_a"
        veth_b = netns_name + "_veth_b"
        to_bridge = pointInfo['to_bridge']
        gw = pointInfo['gw']
        ip = pointInfo['ip']
        cmd_list = [
            "sudo ip netns add {}".format(netns_name),
            "sudo ip netns exec {} ip link set dev lo up ".format(netns_name),
            "sudo ip link add {} type veth peer name {}".format(
                veth_a, veth_b),
            "sudo ip link set {} netns {}".format(veth_a, netns_name),
            "sudo ip netns exec {} ifconfig {} up".format(netns_name, veth_a),
            "sudo ip -n {} addr add {} dev {}".format(netns_name, ip, veth_a),
            "sudo ifconfig {} up".format(veth_b),
            "sudo brctl addif {} {}".format(to_bridge, veth_b),
            "sudo ip netns exec {} route add default gw {}".format(
                netns_name, gw),
            "sudo ip netns exec {} sudo ping -c 10 {} ".format(netns_name, gw),
        ]
        self.call_run(cmd_list)
        if 'tc' in pointInfo.keys():
            cmd_list = []
            if 'egress' in pointInfo['tc'].keys():
                cmd = 'sudo ip netns exec {} sudo tc qdisc add dev {} root netem '.format(
                    netns_name, veth_a)
                if 'delay' in pointInfo['tc']['egress'].keys():
                    cmd = cmd + \
                        " delay {}ms ".format(
                            pointInfo['tc']['egress']['delay'])
                    if 'jitter' in pointInfo['tc']['egress'].keys():
                        cmd = cmd + \
                            " {}ms ".format(
                                pointInfo['tc']['egress']['jitter'])
                if 'loss' in pointInfo['tc']['egress'].keys():
                    cmd = cmd + \
                        " loss {}% ".format(
                            pointInfo['tc']['egress']['loss'])
                cmd_list.append(cmd)
            if 'ingress' in pointInfo['tc'].keys():
                cmd = 'sudo tc qdisc add dev {} root netem '.format(veth_b)
                if 'delay' in pointInfo['tc']['ingress'].keys():
                    cmd = cmd + \
                        " delay {}ms ".format(
                            pointInfo['tc']['ingress']['delay'])
                    if 'jitter' in pointInfo['tc']['ingress'].keys():
                        cmd = cmd + \
                            " {}ms ".format(
                                pointInfo['tc']['ingress']['jitter'])
                if 'loss' in pointInfo['tc']['ingress'].keys():
                    cmd = cmd + \
                        " loss {}% ".format(
                            pointInfo['tc']['ingress']['loss'])
                cmd_list.append(cmd)
            self.call_run(cmd_list)
        self.talk_points.append(pointInfo)

if __name__ == "__main__":
    myinstance = CloudTrafficEngine()
    server = {
        'talk_point': {
            'netns': 'ns_s',
            'to_bridge': 'virbr25',
            'gw': '10.20.25.16',
            'ip': '10.20.25.203/24',
            'tc': {
                'egress': {
                    'delay': 10,
                    'loss': 5,
                },
                'ingress': {
                    'delay': 10,
                    'loss': 5,
                }
            }
        },
        'traffic': {
            'role': 'server',
            'ip': '10.20.25.203',
            'ssl': True,
            'server_name': 'outlook',
            'flow_mode': 'sym',
            'no_print': True,
        }
    }

    client = {
        'talk_point': {
            'netns': 'ns_c',
            'to_bridge': 'virbr24',
            'gw': '10.20.24.15',
            'ip': '10.20.24.203/24',
            'tc': {
                'egress': {
                    'delay': 10,
                    'loss': 5,
                },
                'ingress': {
                    'delay': 10,
                    'loss': 5,
                }
            }

        },
        'traffic': {
            'role': 'client',
            'ip': '10.20.25.203',
            'ssl': True,
            'server_name': 'outlook',
            'flow_mode': 'sym',
            'no_print': True,
            'client_sum': 1000,
            'client_delay': 1,
            'client_concur': 1,

        }
    }
    myinstance.start_traffic(server=server, client=client)
    # import pdb
    # pdb.set_trace()
    time.sleep(2)
    myinstance.stop_traffic()
    myinstance.clear_all_talk_points()

    # import pdb
    # pdb.set_trace()
