# python3
import requests
import sys
import json
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import yaml
from structure_data_check_engine import engine_entrance
from triggers import *


class rest_api_lib:

    def __init__(self, vmanage_ip, username, password,url_lib_path='rest_url/base_url.yaml'):
        self.vmanage_ip = vmanage_ip
        self.session = {}

        if url_lib_path != None:
            with open(url_lib_path, 'r') as f:
                config = f.read()
            self.url_lib = yaml.load(config, Loader=yaml.FullLoader)
        else:
            self.url_lib={}

        self.login(self.vmanage_ip, username, password)

    def login(self, vmanage_ip, username, password):
        """Login to vmanage"""
        base_url_str = 'https://%s/' % vmanage_ip

        login_action = 'j_security_check'

        # Format data for loginForm
        login_data = {'j_username': username, 'j_password': password}

        # Url for posting login data
        login_url = base_url_str + login_action

        url = base_url_str + login_url

        sess = requests.session()

        # If the vmanage has a certificate signed by a trusted authority change
        # verify to True
        login_response = sess.post(
            url=login_url, data=login_data, verify=False)

        if login_response.status_code == 200:
            self.session[vmanage_ip] = sess
            print("*" * 100)
            print("Session info:")
            print("headers:" + format(sess.headers))
            print("auth:" + format(sess.auth))
            print("cookies:" + format(sess.cookies))
            print("*" * 100)
            # import pdb
            # pdb.set_trace()

        else:
            print("Login Failed")

    def client_server(self):
        mount_point = "/client/server"
        # url = self.format_request(vmanage_hostname, mount_point)
        return self.get_request(mount_point)

    def get_jsession_cookie(self, cookies):
        cookie_list = re.split(',|;| ', cookies)
        jsession_cookie = ''
        for c in cookie_list:
            if c.startswith('JSESSIONID'):
                jsession_cookie = c
                break
        return jsession_cookie

    def get_request(self, mount_point):
        """GET request"""
        url = "https://%s/dataservice%s" % (self.vmanage_ip, mount_point)
        # print(url)
        response = self.session[self.vmanage_ip].get(url, verify=False)
        if response.status_code != 200:
            print("Request Failed")
            return None
        else:
            data = response.content
            data_str = str(data, 'utf-8')
            data_json = json.loads(data_str)
            return data_json

    def post_request(self, mount_point, payload={}, headers={'Content-Type': 'application/json'}):
        """POST request"""
        url = "https://%s/dataservice%s" % (self.vmanage_ip, mount_point)
        payload = json.dumps(payload)

        res = self.client_server()
        CSRFToken = res['data']['CSRFToken']
        headers['X-XSRF-TOKEN'] = str(CSRFToken)
        # headers['VSessionId'] = vsessionid

        response = self.session[self.vmanage_ip].post(
            url=url, data=payload, headers=headers, verify=False)
        data = response.content

        data_str = str(data, 'utf-8')
        data_json = json.loads(data_str)
        return data_json
        # import pdb
        # pdb.set_trace()
    
    def get_all_device_cli_template(self):
        """
        Get all device cli template on vmanage
        """
        mount_point = '/template/device?feature=cli'
        # url = self.format_request(vmanage_hostname, mount_point)
        res = self.get_request(mount_point)
        data = res['data']
        return data

    def common_restful_request(self,request_point,return_payload={}):
        url_path = self.url_lib['offset_url'][request_point]['mount_point']
        method = self.url_lib['offset_url'][request_point]['method']
        if method == 'get':
            res = self.get_request(url_path)
        elif method == 'post':
            payload = self.url_lib['offset_url'][request_point]['post_payload']
            res = self.post_request(url_path, payload=payload, headers={'Content-Type': 'application/json'})

            import pdb
            pdb.set_trace()



            import pdb
            pdb.set_trace()

        print("Restful Return Checking")
        res=engine_entrance(res,return_payload)


    # def get_device_cli_template_id_by_name(self, tmp_name):
    #     """
    #     Get device cli template id by template name
    #     """
    #     cli_tmp_info = self.get_all_device_cli_template()
    #     for cli_tmp in cli_tmp_info:
    #         if str(cli_tmp['templateName']) == tmp_name:
    #             tmp_id = str(cli_tmp['templateId'])
    #             return tmp_id
    #     return None

    # def get_device_full_info(self, device_name):
    #     mount_point = '/system/device/vedges?api_key=device/action/status/'
    #     # url = self.format_request(vmanage_hostname, mount_point)
    #     res = self.get_request(mount_point)
    #     # data = res[1]
    #     device_list = res['data']
    #     for device in device_list:
    #         if str(device['host-name']) == device_name:
    #             return device
    #     return None

    # def wait_for_template_task_to_complete(self, mount_point_key, task_status="Success"):
    #     """
    #     Keeps polling until the template device action is done
    #     @param vmanage_hostname:
    #     @param mount_point_key:
    #     @return: list of the status
    #     """
    #     import time
    #     # url = self.format_request(
    #     #     vmanage_hostname, '/device/action/status/' + mount_point_key)

    #     mount_point = '/device/action/status/' + str(mount_point_key)

    #     result = self.get_request(mount_point)
    #     timeout = time.time() * 60
    #     statusList = []

    #     while result['summary']['status'] != 'done':
    #         # keep polling until the device action is done
    #         result = self.get_request(mount_point)

    #     if 'Failure' in result['summary']['count'].keys():
    #         print("Push failed")
    #     else:
    #         print("Push Success")

    #     # import pdb
    #     # pdb.set_trace()
    #     # tasksDict = result[1]['data']

    #     # for action in tasksDict:
    #     #     if action['status'] == task_status:
    #     #         statusList.append(True)
    #     #     else:
    #     #         statusList.append(False)
    #     # return statusList

    # def attach_device_cli_template_to_device(self, template_name=None, device_name=None):
    #     """
    #     Attach a device cli template to a machines
    #     """
    #     print("Push template {} to device {}".format(template_name, device_name))
    #     tmp_id = self.get_device_cli_template_id_by_name(template_name)
    #     mount_point = '/template/device/config/attachcli?api_key=device/action/status/'
    #     device_info = self.get_device_full_info(device_name)
    #     payload = {
    #         "deviceTemplateList": [
    #             {
    #                 "templateId": tmp_id,
    #                 "device": [
    #                     {
    #                         "csv-status": "complete",
    #                         "csv-deviceId": str(device_info['uuid']),
    #                         "csv-deviceIP": str(device_info['system-ip']),
    #                         "csv-host-name": device_name,
    #                         "//system/host-name": device_name,
    #                         "//system/system-ip": str(device_info['system-ip']),
    #                         "//system/site-id": str(device_info['site-id']),
    #                         "csv-templateId": tmp_id,
    #                         "selected": "true"
    #                     }
    #                 ],
    #                 "isEdited": 'false',
    #                 "isMasterEdited": 'false'
    #             }
    #         ]
    #     }

    #     response = self.post_request(mount_point, payload)

    #     task_id = response['id']
    #     res = self.wait_for_template_task_to_complete(task_id)

    # def change_to_cli_mode(self, device_name):
    #     """
    #     Modify deivce to CLI mode
    #     """
    #     print("Change device {} back to CLI mode".format(device_name))
    #     mount_point = '/template/config/device/mode/cli'
    #     device_info = self.get_device_full_info(device_name)
    #     payload = {
    #         "deviceType": device_info["deviceType"],
    #         "devices": [
    #             {
    #                 "deviceId": device_info["uuid"],
    #                 "deviceIP": device_info["system-ip"]
    #             }
    #         ]
    #     }
    #     response = self.post_request(mount_point, payload)
    #     task_id = response['id']
    #     res = self.wait_for_template_task_to_complete(task_id)


def main():
    vmanage_ip = "10.75.28.100:9912"
    username = "sish"
    password = "sish"
    while True:
        obj = rest_api_lib(vmanage_ip, username, password)
        response = obj.change_to_cli_mode('vm5')
        response = obj.attach_device_cli_template_to_device(
            'fugazi_cli', 'vm5')


    obj = rest_api_lib(vmanage_ip, username, password)
    response = obj.change_to_cli_mode('vm5')
    response = obj.attach_device_cli_template_to_device(
        'clean_config', 'vm5')
    response = obj.change_to_cli_mode('vm5')

if __name__ == "__main__":

    vmanage_ip = "10.75.28.100:9912"
    username = "sish"
    password = "sish"
    obj = rest_api_lib(vmanage_ip, username, password)

    ##################################
    ## Load url <--> data modle ######
    ##################################
    mapping_file='url_data_mapping.yaml'
    with open(mapping_file, 'r') as f:
        config = f.read()
    mapping_dict = yaml.load(config, Loader=yaml.FullLoader)

    #####################################
    ## Operate Each URL point Order #####
    #####################################
    for order in mapping_dict['mapping']:
        url_point = order['url']
        feed_data = order['feed_data']
        detail_url_info = obj.url_lib['offset_url'][url_point]

        #####################################
        ## If Trigger Operation Needed  #####
        #####################################
        if 'trigger' in detail_url_info.keys():
            print("Start Trigger Funcs")
            trigger_funs=detail_url_info['trigger']
            for funs in trigger_funs:
                funs_name =  funs['method']
                funs_inputs =  funs['input_dict']
                import pdb;pdb.set_trace()
                res = globals()[funs_name](**funs_inputs)
            print("Ended Trigger Funcs")


        print("Checking URL:{} \r\nFeed Data:{}".format(obj.url_lib['offset_url'][url_point]['mount_point'],feed_data))

        #####################################
        ## Get Feed data template       #####
        #####################################
        with open('rest_data/'+feed_data+'.yaml', 'r') as f:
            config = f.read()
        return_payload = yaml.load(config, Loader=yaml.FullLoader)

        #####################################
        ## Checking RESTFUL interface!  #####
        #####################################
        res=obj.common_restful_request(url_point,return_payload=return_payload)



    # sish='url_data_mapping.yaml'
    # with open(sish, 'r') as f:
    #     config = f.read()
    # expect_dict = yaml.load(config, Loader=yaml.FullLoader)

    # import pdb
    # pdb.set_trace()


    # sish='rest_data/demo.yaml'
    # with open(sish, 'r') as f:
    #     config = f.read()
    # expect_dict = yaml.load(config, Loader=yaml.FullLoader)

    # res=engine_entrance(res,expect_dict)
    # print(res)

    # import pdb
    # pdb.set_trace()



    # while True:
    #     obj = rest_api_lib(vmanage_ip, username, password)
    #     response = obj.change_to_cli_mode('vm5')
    #     response = obj.attach_device_cli_template_to_device(
    #         'fugazi_cli', 'vm5')

    
    # obj = rest_api_lib(vmanage_ip, username, password)
    # response = obj.change_to_cli_mode('vm5')
    # response = obj.attach_device_cli_template_to_device(
    #     'clean_config', 'vm5')
    # response = obj.change_to_cli_mode('vm5')



    # sish='/rest_url/base_url.yaml'
    # with open(sish, 'r') as f:
    #     config = f.read()
    # url_dicts = yaml.load(config, Loader=yaml.FullLoader)
    # request_point = 'cli'

    # common_restful_request(request_point)





    # import urllib3
    # http = urllib3.PoolManager(timeout=30)
    # body_data = {"capabilities": {"firstMatch": [{}], "alwaysMatch": {"browserName": "firefox", "acceptInsecureCerts": 'true'}}, "desiredCapabilities": {
    #     "browserName": "firefox", "acceptInsecureCerts": 'true', "marionette": 'true'}}
    # headers = {'Accept': 'application/json', 'Content-Type': 'application/json;charset=UTF-8',
    #            'User-Agent': 'selenium/3.141.0 (python mac)', 'Connection': 'keep-alive'}
    # # resp = http.request('POST', 'http://127.0.0.1:62004/session',
    # #                     body=body_data, headers=headers)

    # sess = requests.session()
    # login_url = 'http://127.0.0.1:62004'

    # # If the vmanage has a certificate signed by a trusted authority change
    # # verify to True
    # login_response = sess.post(
    #     url=login_url, data=body_data, verify=False)

    # # body_data = {"capabilities": {"firstMatch": [{}], "alwaysMatch": {"browserName": "firefox", "acceptInsecureCerts": "true"}}, "desiredCapabilities": {
    # #     "browserName": "firefox", "acceptInsecureCerts": "true", "marionette": "true"}}
    # # res = requests.post('http://127.0.0.1:4444/session', data=body_data)
    # import pdb
    # pdb.set_trace()
