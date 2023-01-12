from bridge_vnet_vm import bridge_of_vms
import yaml
from string import Template

def load_yaml_update(file,update_dict=None):
    with open(file) as f:
        filecontent = f.read()
    if update_dict is not None:
        template = Template(filecontent)
        res = template.substitute(update_dict)
    else:
        res = filecontent
    return yaml.load(res, Loader=yaml.FullLoader)

def load_app_traffic_profile():
    config_file = '/home/tester/vtest/tests/scripts/setup_configs/nwpi_p4/app_traffic.yaml'
    query_dict={
        'vm11':[3],
        'vm1': [2,5],
        'vm2':[4],
        'vm3': [15],
        'vm7': [56,24],
        'vm6': [25,60],
        'vm13': [20],
    }
    res = bridge_of_vms(query_dict)
    update_dicts = {
        'virbr3': res['vm11'][3],
        'virbr2': res['vm1'][2],
        'virbr4': res['vm2'][4],
        'virbr15': res['vm3'][15],
        'virbr5': res['vm1'][5],
        'virbr56': res['vm7'][56],
        'virbr24': res['vm7'][24],
        'virbr25': res['vm6'][25],
        'virbr20': res['vm13'][20],
        'virbr60': res['vm6'][60],
    }
    res = load_yaml_update(config_file,update_dicts)
    with open(r'/tmp/nwpi_p4_app_traffic.yaml', 'w') as file:
        yaml.dump(res, file)
    return res

if __name__ == '__main__':
    load_app_traffic_profile()
     
