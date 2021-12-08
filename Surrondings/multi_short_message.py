# Example for creating your program by specifying buffers to send, without relaying on pcap file
#  sudo ./t-rex-64 -i --astf
# ./t-rex-64 -f /root/art_trex/multi_short_message.py -m 1 -d 1 -c 1 -l 1000  --astf  --cfg /root/art_trex/trex_cfg.yaml



from trex.astf.api import *
import argparse


# we can send either Python bytes type as below:
http_req = b'GET /3384 HTTP/1.1\r\nHost: 22.0.0.3\r\nConnection: Keep-Alive\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322; .NET CLR 2.0.50727)\r\nAccept: */*\r\nAccept-Language: en-us\r\nAccept-Encoding: gzip, deflate, compress\r\n\r\n'
# or we can send Python string containing ascii chars, as below:
http_response_template = 'HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/6.0\r\nContent-Type: text/html\r\nContent-Length: 32000\r\n\r\n<html><pre>{0}</pre></html>'
http_req_template = 'This is request {0}'

http_req2=http_req_template.format('*'*10)
http_req3=http_req_template.format('*'*500)
http_req4=http_req_template.format('*'*10)

http_response2 = http_response_template.format('*'*2000)
http_response3 = http_response_template.format('*'*5000)
http_response4 = http_response_template.format('*'*5000)



class Prof1():
    def __init__(self):
        pass  # tunables

    def create_profile(self,res_size):
        # client commands
        http_response = http_response_template.format('*'*10000000)
        # http_response = http_response_template.format('*'*500000)
        http_response = http_response_template.format('*'*14600)
        # print("client_send_bytes:"+str(2*len(http_response)))
        # print("server_send_bytes:"+str(2*len(http_req)))
        
        info = ASTFGlobalInfo()
        mss =1460
        info.tcp.do_rfc1323 =0
        info.tcp.mss = mss
        info.tcp.rxbufsize = 3*mss  # split the buffer to MSS and ack every buffer, no need the no_delay option
        info.tcp.txbufsize = 4*mss     
        # info.tcp.delay_ack_msec = 20
        info.tcp.keepintvl = 60
        info.tcp.keepinit = 60
        info.tcp.keepidle = 60


        ########################
        ##### client  ##########
        ########################
        prog_c = ASTFProgram()
        prog_c.connect()
        prog_c.delay_rand(1000,100000);   #1ms - 100ms
        # prog_c.delay(30000000);   #30s
        prog_c.send(http_req)
        prog_c.recv(len(http_response))


        prog_c.set_var("var2",10); # set var 0 to 10 
        prog_c.set_label("a:");

        # prog_c.delay(300000);
        prog_c.delay_rand(10000,1000000);   #1ms - 100ms
        prog_c.send(http_req2)
        prog_c.recv(len(http_response2))


        prog_c.jmp_nz("var2","a:") # dec var "var2". in case it is *not* zero jump a: 

        # prog_c.delay(240000000);   #30s
        prog_c.delay(100000);

        ########################
        ##### server  ##########
        ########################
        prog_s = ASTFProgram()
        prog_s.accept()

        prog_s.recv(len(http_req))
        prog_s.delay(100000); #delay 0.5
        prog_s.send(http_response)  


        prog_s.set_var("var3",10); # set var 0 to 10 
        prog_s.set_label("b:");

        prog_s.recv(len(http_req2))
        prog_s.delay(100000); #delay 0.5
        prog_s.send(http_response2)


        prog_s.jmp_nz("var3","b:") # dec var "var2". in case it is *not* zero jump a: 



        prog_s.wait_for_peer_close()








        # prog_c = ASTFProgram()
        # prog_c.connect()
        # prog_c.delay_rand(100,200);   #200us

        # prog_s = ASTFProgram()
        # prog_s.accept()
        # prog_s.wait_for_peer_close()
       

        # ######### Message exchange ###########
        # http_response = http_response_template.format('*'*1000)
        # prog_c.send(http_req)
        # prog_c.recv(len(http_response))

        # prog_s.recv(len(http_req))
        # prog_s.delay(100000); #delay 0.5
        # prog_s.send(http_response)  


        # http_req2 = http_req_template.format('8'*1000)
        # http_response = http_response_template.format('*'*5000)
        # prog_c.delay(30000);
        # prog_c.send(http_req2)
        # prog_c.recv(len(http_response))

        # prog_s.recv(len(http_req2))
        # prog_s.delay(100000); #delay 0.5
        # prog_s.send(http_response)


        # http_req2 = http_req_template.format('8'*10)
        # http_response = http_response_template.format('*'*50)
        # prog_c.delay(50000);
        # prog_c.send(http_req2)
        # prog_c.recv(len(http_response))

        # prog_s.recv(len(http_req2))
        # prog_s.delay(100000); #delay 0.5
        # prog_s.send(http_response)




        ip_gen_c = ASTFIPGenDist(ip_range=["16.0.0.1", "16.0.0.255"], distribution="seq")
        ip_gen_s = ASTFIPGenDist(ip_range=["48.0.0.1", "48.0.0.255"], distribution="seq")
        ip_gen = ASTFIPGen(glob=ASTFIPGenGlobal(ip_offset="0.0.0.1"),
                           dist_client=ip_gen_c,
                           dist_server=ip_gen_s)


        # template
        # tcp_params = ASTFTCPInfo(window=32768)
        temp_c = ASTFTCPClientTemplate(program=prog_c,  ip_gen=ip_gen,
            # tcp_info=tcp_params
            )
        temp_s = ASTFTCPServerTemplate(program=prog_s,
        # tcp_info=tcp_params
        )  # using default association
        template = ASTFTemplate(client_template=temp_c, server_template=temp_s)

        # profile
        profile = ASTFProfile(default_ip_gen=ip_gen, templates=template,
                              default_c_glob_info=info,
                              default_s_glob_info=info
                            )
        return profile

    def get_profile(self, tunables, **kwargs):
        parser = argparse.ArgumentParser(description='Argparser for {}'.format(os.path.basename(__file__)), 
                                         formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        parser.add_argument('--size',
                            type=int,
                            default=1,
                            help='The response size')

        args = parser.parse_args(tunables)
        res_size= args.size
        return self.create_profile(res_size)


def register():
    return Prof1()
