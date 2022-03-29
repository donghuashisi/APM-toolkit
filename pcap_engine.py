from scapy.all import *
import os
import re
from pcap_splitter.splitter import PcapSplitter
import shutil

global dns_info
dns_info = {}


def get_pcap_list(pcap_dir):
    exiting_log = os.popen("ls " + pcap_dir)
    log_list = exiting_log.read()
    log_list = log_list.split("\n")
    log_list.remove("")
    return log_list


def func1():
    dir_location = "/Users/sish/Desktop/APM-toolkit/sish/"
    # dir_location2 = "/root/temp"
    # origin_pcap_file = '/root/sish.pcap'
    origin_pcap_file = './1.pcap'

    # shutil.rmtree(dir_location)
    # os.makedirs(dir_location)

    ps = PcapSplitter(origin_pcap_file)
    ps.split_by_session(dir_location)
    pcap_list = get_pcap_list(dir_location)
    for one_pcap in pcap_list:
        flow_parse(dir_location, one_pcap)


def update_application_info():
    dir_location = "/root/temp/"
    application_parse()
    pcap_list = get_pcap_list(dir_location)
    for one_pcap in pcap_list:
        flow_parse(dir_location, one_pcap)


def func2():
    pcap_pattern = 'saas(.*)'
    dir_location = "/root/temp/"
    pcap_list = get_pcap_list(dir_location)
    for one_pcap in pcap_list:
        if re.match(pcap_pattern, one_pcap) != None:
            flow_parse(dir_location, one_pcap)


def application_parse():
    pcap_pattern = 'dns_(.*)'
    dir_location = "/root/temp/"
    pcap_list = get_pcap_list(dir_location)
    for one_pcap in pcap_list:
        if re.match(pcap_pattern, one_pcap) != None:
            scapy_cap = rdpcap(dir_location + one_pcap)
            DNS_Response_parse(scapy_cap[1])
    for domain_name in dns_info.keys():
        print(domain_name + "  " + "{}".format(dns_info[domain_name]))


def DNS_Response_parse(scapy_cap):
    global dns_info
    ans_count = scapy_cap[DNS].ancount
    domain_name = scapy_cap[DNS].qd.qname.decode("utf-8")
    host_ip = []
    for ans_num in range(ans_count):
        if scapy_cap[DNS].an[DNSRR][ans_num].type == 1:
            host_ip.append(scapy_cap[DNS].an[DNSRR][ans_num].rdata)
    dns_info[domain_name] = host_ip


def find_domain_name_from_ip(ip):
    for key in dns_info.keys():
        if ip in dns_info[key]:
            return key
    return None


def flow_parse_v6(scapy_cap):
    # scapy_cap = rdpcap(dir_location + one_pcap)
    post_name = None
    if IPv6 in scapy_cap[0]:
        print("IPv6 flow process!")
        src = scapy_cap[0][IPv6].src
        dst = scapy_cap[0][IPv6].dst
        pkt_num = len(scapy_cap)
        if scapy_cap[0][IPv6].nh == 1:
            # ICMP session
            session_info = str(src) + ':' + str(dst) + "."
            post_name = 'ipv6_icmp_' + session_info

        elif scapy_cap[0][IPv6].nh == 6:
            # TCP session
            sport = scapy_cap[0][IPv6][TCP].sport
            dport = scapy_cap[0][IPv6][TCP].dport

            session_info = str(src) + ':' + str(dst) + ':' + \
                str(sport) + ':' + str(dport) + ':' + str(pkt_num) + "."
            post_name = 'ipv6_tcp_' + session_info

        elif scapy_cap[0][IPv6].nh == 17 and DNS in scapy_cap[0]:
            # UDP session
            sport = scapy_cap[0][IPv6][UDP].sport
            dport = scapy_cap[0][IPv6][UDP].dport

            if scapy_cap[0][UDP].dport == 53:
                # unicast DNS session
                if len(scapy_cap) != 2:
                    print("Uknow flow:{}".format(one_pcap))
                    return post_name
                ###### DNS request #######
                dns_Qry = scapy_cap[0]
                dns_Ans = scapy_cap[1]
                domain_name = scapy_cap[0][DNS].qd[DNSQR].qname.decode("utf-8")
                post_name = 'ipv6_dns_' + domain_name + '_' + str(src) + ':' + str(dst) + ':' + \
                    str(sport) + ':' + str(dport) + ':' + str(pkt_num) + "."

            elif scapy_cap[0][UDP].dport == 5353:
                # multicasrt DNS session
                # dns_Qry = scapy_cap[0][DNS].qd.qname
                # dns_Ans = scapy_cap[1]
                if scapy_cap[0][DNS].qd != None and scapy_cap[0][DNS].qd.qname != None:
                    domain_name = scapy_cap[0][DNS].qd.qname.decode("utf-8")
                    post_name = 'ipv6_muldns_' + domain_name
            else:
                # Normal UDP session flow
                session_info = str(src) + ':' + str(dst) + ':' + \
                    str(sport) + ':' + str(dport) + ':' + str(pkt_num) + "."
                post_name = 'ipv6_udp_' + session_info
    return post_name


def flow_parse(dir_location, one_pcap):
    print("Parse :{}".format(one_pcap))
    post_name = None

    if re.match(".*\.pcap", one_pcap) == None:
        print("{} is not a pcap file".format(one_pcap))
        return
    scapy_cap = rdpcap(dir_location + one_pcap)
    if IP not in scapy_cap[0]:
        post_name = flow_parse_v6(scapy_cap)
        if post_name == None:
            return
    else:
        src = scapy_cap[0][IP].src
        dst = scapy_cap[0][IP].dst
        pkt_num = len(scapy_cap)
        app = 'Unknows'
        if dns_info != {}:
            app = find_domain_name_from_ip(dst)
            if app == None:
                app = 'Unknows'
        if scapy_cap[0][IP].proto == 1:
            # ICMP session
            session_info = str(src) + ':' + str(dst) + "."
            post_name = 'icmp_' + session_info

        elif scapy_cap[0][IP].proto == 6:
            # TCP session
            # import pdb
            # pdb.set_trace()
            sport = scapy_cap[0][IP][TCP].sport
            dport = scapy_cap[0][IP][TCP].dport
            # import pdb
            # pdb.set_trace()

            session_info = str(src) + ':' + str(dst) + ':' + \
                str(sport) + ':' + str(dport) + ':' + str(pkt_num) + "."
            post_name = 'tcp_' + 'app:' + app + '_' + session_info

        elif scapy_cap[0][IP].proto == 17:
            # UDP session
            sport = scapy_cap[0][IP][UDP].sport
            dport = scapy_cap[0][IP][UDP].dport

            if scapy_cap[0][UDP].dport == 53 and DNS in scapy_cap[0]:
                # DNS session
                if len(scapy_cap) != 2:
                    print("Uknow flow:{}".format(one_pcap))
                    return
                ###### DNS request #######
                dns_Qry = scapy_cap[0]
                dns_Ans = scapy_cap[1]
                domain_name = scapy_cap[0][DNS].qd[DNSQR].qname.decode("utf-8")
                post_name = 'dns_' + domain_name + '_' + str(src) + ':' + str(dst) + ':' + \
                    str(sport) + ':' + str(dport) + ':' + str(pkt_num) + "."

            elif scapy_cap[0][UDP].dport == 5353:
                # Multicasrt DNS session
                print("Multicast DNS flow, Skip!!!".format(one_pcap))
                return
            else:
                # Normal UDP session flow
                session_info = str(src) + ':' + str(dst) + ':' + \
                    str(sport) + ':' + str(dport) + ':' + str(pkt_num) + "."
                post_name = 'udp_' + 'app:' + app + '_' + session_info
    if post_name != None:
        os.rename(dir_location + one_pcap, dir_location +
                  post_name + 'pcap')

def art_measure(dir_location):
    pcap_list = get_pcap_list(dir_location)
    server_dst={}
    for one_pcap in pcap_list:
        scapy_cap = rdpcap(dir_location + one_pcap)
        try:
            if scapy_cap[0][IP].proto == 6:
                if scapy_cap[0]['TCP'].flags.value == 2 and scapy_cap[1]['TCP'].flags.value == 18 and scapy_cap[2]['TCP'].flags.value == 16:
                    sip = scapy_cap[0][IP].src
                    dip = scapy_cap[0][IP].dst
                    sport = scapy_cap[0][IP][TCP].sport
                    dport = scapy_cap[0][IP][TCP].dport
                    snd = scapy_cap[1].time - scapy_cap[0].time
                    cnd = scapy_cap[2].time - scapy_cap[1].time

                    fit_key = str(dip)+ ' '+str(dport)
                    if fit_key not in server_dst.keys():
                        server_dst[fit_key]=[]
                    server_dst[fit_key].append("{} {} <---> {} {}: art:{} {}".format(sip,sport,dip,dport,snd,cnd))
        except Exception as e:
            print("{} Issued TCP session".format(one_pcap))
        else:
            pass
        finally:
            pass

    for app_dst in server_dst.keys():
        for session in server_dst[app_dst]:
            print(session)




# ###### split flow first ###########
# flow_parse("./",
#            "vm5.pcap")

func1()
art_measure("/Users/sish/Desktop/APM-toolkit/sish/")
# ####################################

###### update flow infomation#######
# application_parse()
# update_application_info()
####################################

# ###### parse one flow ##############
# flow_parse("/root/temp/",
#            "tcp_app:webshell.suite.office.com._10.140.36.26:52.111.240.3:50124:443:125.pcap")
# ####################################

#         pdb.set_trace()

#     main()

# if re.match(".*\.pcap", one_pcap) != None:
#
#     import pdb
#     pdb.set_trace()
#     scapy_cap = rdpcap(dir_location + one_pcap)
#     for packet in scapy_cap:
#         import pdb
#         pdb.set_trace()
#         # print packet[IPv6].src
