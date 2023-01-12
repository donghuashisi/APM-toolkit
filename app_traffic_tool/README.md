# Overview
This is a vtest native traffic generator tool. 
Unlike trex, you need an addtional ubuntu vm, it is cloud native solution.
We leverage  (1) basic network features suppoted by linux such as tc,ip-netns,ip-link,brctl
(2) linux tcp/ip stack and socket programming API to achieve it.

# What it provide
(1) Beacase we leavage socket programming to generate traffic, so it is statful and app-aware if you use ssl layer.
(2) Server instance can also be used to simulate APP server for some features need to probe server.
(3) Traffic transaction can be customermized to define the application payload pattern.

# How to use it
(1) Define clients and servers info just in a yaml file (./demo.yaml as an reference) and use standalone tool to send traffic.

    base:
        servers:
            - talk_point:
                to_bridge: 'virbr25'   <-- vswith need to bridge
                gw: '10.20.25.16'      <-- gateway ip
                ip: '10.20.25.110/24'  <-- host ip
                traffic:
                - name: 's1'     <-- server unique identity
                    ip: '10.20.25.110'   <-- server ip (same as host ip)
                    ssl: True   <-- ssl enabled
                    server_name: 'www.sharepoint.com'  <-- server name in SSL layer
                    flow_mode: 'sym' <-- application layer trsaction pattern
                    no_print: True
        clients:
            - talk_point:
                to_bridge: 'virbr24'
                gw: '10.20.24.15'
                ip: '10.20.24.110/24'
                traffic:
                - s_name: 's1'   <-- server client need to talk
                    no_print: True
                    client_sum: 100000   <--- total 100000 connections
                    client_delay: 1
                    client_concur: 5   <--- 5 alive connections at one time

    Traffic Profile in above example:

    client(10.20.24.110) -------virbr25---------- (10.20.24.25)vm5
                                                                |
                    usually sdwan tunnel in most testbed --->   |
                                                                |
    sharepoint server(10.20.25.110) ---virbr24---- (10.20.25.16)vm6


   Then send traffic standalone:  
        python3 orchestrator.py --yaml YOUR_YAML_FILE --case A_PROFILE  
   For example:  
        python3 orchestrator.py --yaml ./demo.yaml --case base (make sure bridge && ip matched in your testbed)  
   If you need to deloy below cases:  
        (1) multi servers && multi clients  
        (2) multi servers && single client  
        (3) single servers && multi clients  
        Please refer ~/vtest/tests/sessions/app_traffic_profile/app_perf/app_server_client.yaml  

(2) If you want to include it in automation, just import module and call APIs

        from cloud_traffic_generator.orchestrator import CloudTrafficManager  
        a_instance = CloudTrafficManager()  
        a_instance.start_traffic(server=SERVERS, client=CLIENTS)  <-- customize SERVERS && CLIENTS dict like demo.yaml  
        (For more APIs usage, please read orchestrator.py)
