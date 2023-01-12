from __future__ import print_function
import subprocess
from collections import OrderedDict
import re


def parse_bridge():
    """parse outpout for get_virsh_domiflist"""
    output = subprocess.getoutput("brctl show")
    bridgeDict = {}
    lines = output.splitlines()
    lines = [line.strip() for line in lines]
    currentBridge = None
    for line in lines:
        res = line.split()
        if len(res) > 1:
            bridgeName = res[0]
            currentBridge = bridgeName
            bridgeId = res[1]
            # bridgeSTP = res[2]
            if bridgeName not in bridgeDict.keys():
                bridgeDict[bridgeName] = {}
                bridgeDict[bridgeName]['id'] = bridgeId
                bridgeDict[bridgeName]['intfs'] = []
            if len(res) == 4:
                member0 = res[3]
                bridgeDict[bridgeName]['intfs'].append(member0)
        elif len(res) == 1:
            bridgeDict[currentBridge]['intfs'].append(res[0])
    return bridgeDict


def get_bridge_add_to(vethName, bridgeDict=None):
    if bridgeDict is None:
        bridgeDict = parse_bridge()
    for key in bridgeDict.keys():
        if vethName in bridgeDict[key]['intfs']:
            return key
    return None


def get_virsh_domiflist(machine, debug_dump=False):
    """parse outpout for get_virsh_domiflist"""

    output = subprocess.getoutput("virsh domiflist {0}".format(machine))
    domiflist = OrderedDict()

    # Split lines for further processing
    lines = output.splitlines()
    # Remove leading and trailing white spaces
    lines = [line.strip() for line in lines]

    for line in lines:
        line = line.lower()
        # Ignoring Empty lines and the -------- line
        if re.match(r'^\s*$', line) or re.match(r'^--------', line):
            continue

        if 'network' in line:
            tokens = line.split()
            key_string = tokens[2]
            dom_iface = OrderedDict()
            domiflist[key_string] = dom_iface
            dom_iface['interface'] = tokens[0]
            dom_iface['type'] = tokens[1]
            dom_iface['source'] = tokens[2]
            dom_iface['model'] = tokens[3]
            dom_iface['mac'] = tokens[4]

    # if debug_dump:
    #     logger.info(domiflist)

    return domiflist


def vnic_from_vnet(machine, vnet):
    """retur vnic interface based on vnet id"""
    vnic = None
    domiflist = get_virsh_domiflist(machine)
    vnet = 'vnet' + str(vnet)
    if vnet in domiflist:
        vnic = domiflist[vnet]['interface']
    return vnic


def bridge_of_vms(query_dicts):
    bridgeDict = parse_bridge()
    reply_dict = {}
    for vm in query_dicts:
        vnets = query_dicts[vm]
        reply_dict[vm] = {}
        for vnet in vnets:
            reply_dict[vm][vnet] = get_bridge_add_to(vnic_from_vnet(vm, vnet), bridgeDict)
    return reply_dict


if __name__ == "__main__":
    query_dict = {
        'vm11': [3],
        'vm1': [2, 5],
        'vm2': [4],
        'vm3': [15],
        'vm7': [56, 24],
        'vm6': [25],
        'vm13': [20],
    }
    print((bridge_of_vms(query_dict)))
