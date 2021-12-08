import sys
sys.path.append(
    '/home/cisco/python3.9.6_venv/lib/python3.9/my_lib/trex_client/interactive/')
sys.path.append(
    '/home/cisco/python3.9.6_venv/lib/python3.9/my_lib/trex_client/')
from trex.astf.api import *
import yaml as yml
from pprint import pprint
import argparse
import sys
import trex.examples.astf.ndr_bench as ndr
import logging

logger = logging.getLogger(__name__)
import signal
from baselibs import NDR

NDR_stop = False
NDR_instance = None


class MyASTFNdrBench(ndr.ASTFNdrBench):

    def __init__(self,
                 astf_client=None,
                 high_mult=100000,
                 low_mult=1000,
                 uut=None,
                 tgen=None,
                 server='127.0.0.1',
                 iteration_duration=30.00,
                 title='Title',
                 verbose=True,
                 allowed_error=1.00,
                 q_full_resolution=2.00,
                 max_iterations=10,
                 latency_pps=0,
                 max_latency=0,
                 lat_tolerance=0,
                 output=None,
                 yaml_file=None,
                 plugin_file=None,
                 tunables={},
                 profile='/home/cisco/elastic_art/udp_mix.py',
                 profile_tunables={},
                 stl_check=True,
                 check_only_on_uut=True,
                 uut_intf_list=[],
                 peerList=[],
                 drop_cause=['TailDrop'],
                 log_file=None,
                 feature='',
                 ):

        if title == 'Title':
            title = profile.split('/')[-1].split(".")[0]
        configs = {'high_mult': high_mult, 'low_mult': low_mult, 'server': server,
                   'iteration_duration': iteration_duration, 'verbose': verbose,
                   'allowed_error': allowed_error, 'title': title, 'q_full_resolution': q_full_resolution,
                   'max_iterations': max_iterations, 'latency_pps': latency_pps,
                   'max_latency': max_latency, 'lat_tolerance': lat_tolerance,
                   'plugin_file': plugin_file, 'tunables': tunables}

        if astf_client == None:
            self.c = ASTFClient(server=server)
        else:
            self.c = astf_client
        # connect to server
        self.c.connect()
        # take all the ports
        self.c.reset()
        self.c.load_profile(profile=profile, tunables=profile_tunables)

        config = ndr.ASTFNdrBenchConfig(**configs)

        super().__init__(astf_client=self.c, config=config)

        ####### set system signal handler #######
        global NDR_instance
        NDR_instance = self
        signal.signal(signal.SIGTSTP, NDR.my_handler)
        import os
        #####################
        self.pid = os.getpid()
        self.multi_list = []
        self.debug_log_info()
        #############
        self.uut = uut
        self.tgen = tgen

        self.error_flag = None
        self.errors = None
        self.stl_check = stl_check
        self.check_only_on_uut = check_only_on_uut
        self.feature = feature
        self.tgen_NDR = NDR.NDR(tgen=self.tgen,
                                uut=self.uut,
                                skip_debug=True,
                                uut_intf_list=uut_intf_list,
                                peerList=peerList,
                                drop_cause=drop_cause,
                                log_file=log_file,
                                feature=feature,
                                )

        self.my_find_ndr()
        # self.c.disconnect()

    def debug_log_info(self):
        logger.info(">>>>>>>>>>>>>>>>>>>>>>\r\n" * 10)
        logger.info("Debug Input: kill -TSTP {}".format(self.pid))
        logger.info(">>>>>>>>>>>>>>>>>>>>>>\r\n" * 10)

    def measure_traffic_rate(self):
        # self.config.latency_pps :0
        self.astf_client.start(
            mult=self.multi_list[-1], nc=True, latency_pps=self.config.latency_pps)
        time.sleep(30)
        self.tgen_NDR.get_qfp_util(self.uut)
        self.tgen_NDR.recored_data_on_uut('emix', throughput='')
        self.astf_client.stop()

    def package_result(self, stats):
        ############# Parese result ############
        opackets = stats['total']['opackets']
        ipackets = stats['total']['ipackets']
        q_full_packets = stats['global']['queue_full']
        q_full_percentage = float((q_full_packets / float(opackets)) * 100.000)
        latency_stats = stats['latency']
        latency_groups = {}
        if latency_stats:
            for i in latency_stats.keys():
                if type(i) != int:
                    continue
                latency_dict = latency_stats[i]['hist']
                latency_groups[i] = latency_dict
        tx_bps = stats['total']['tx_bps']
        rx_bps = stats['total']['rx_bps']
        tx_util_norm = stats['total']['tx_util'] / \
            self.astf_client.get_port_count()
        self.results.stats['total_iterations'] += 1
        run_results = {'error_flag': self.error_flag, 'errors': self.errors, 'queue_full_percentage': q_full_percentage,
                       'valid_latency': self.is_valid_latency(latency_stats),
                       'rate_tx_bps': tx_bps,
                       'rate_rx_bps': rx_bps,
                       'tx_util': tx_util_norm, 'latency': latency_groups,
                       'cpu_util': stats['global']['cpu_util'], 'tx_pps': stats['total']['tx_pps'],
                       'bw_per_core': stats['global']['bw_per_core'], 'rx_pps': stats['total']['rx_pps'],
                       'total_tx_L1': stats['total']['tx_bps_L1'],
                       'total_rx_L1': stats['total']['rx_bps_L1'], 'tx_bps': stats['total']['tx_bps'],
                       'rx_bps': stats['total']['rx_bps'],
                       'total_iterations': self.results.stats['total_iterations']}
        return run_results

    def start_traffic(self, mult=100):
        self.astf_client.stop()
        if mult == None:
            mult = self.multi_list[-1]

        self.astf_client.start(
            mult=mult, nc=True, latency_pps=self.config.latency_pps)

    def stop_traffic(self):
        self.astf_client.stop()

    def perf_run(self, mult):
        """
        """
        self.debug_log_info()
        self.multi_list.append(mult)
        logger.info("*" * 20 + "Iteration:{}".format(mult) + "*" * 20)
        logger.info("multi_list:{}".format(self.multi_list))

        ############# start traffic on trex client ############
        self.astf_client.stop()
        self.tgen_NDR.clear_pkt_drop(uut=self.uut)

        # allow time for counters to settle from previous runs
        time.sleep(10)
        self.astf_client.clear_stats()
        self.astf_client.start(
            mult=mult, nc=True, latency_pps=self.config.latency_pps)
        time_slept = 0
        sleep_interval = 1  # in seconds
        error_flag = False

        time.sleep(self.config.iteration_duration)
        stats = self.astf_client.get_stats()
        self.error_flag, self.errors = self.astf_client.is_traffic_stats_error(stats[
            'traffic'])

        rx_pps = stats['total']['rx_pps']
        tx_pps = stats['total']['tx_pps']
        loss = abs(float(rx_pps) - float(tx_pps)) / float(tx_pps)

        if self.tgen != None:
            self.tgen_NDR.one_round()  # need to trigger some session
            time.sleep(1)
            loss = self.tgen_NDR.get_total_loss()
            if loss == 0:
                self.error_flag = False
                self.errors = {}

        self.tgen_NDR.get_qfp_util(self.uut)

        self.astf_client.stop()

        res = self.tgen_NDR.get_pkt_drop()
        get_drop = self.tgen_NDR.find_rational_drop_caues(res, get_return=True)

        logger.info(
            "." * 20 + "rx_pps:{}, tx_pps:{}, loss:{}".format(rx_pps, tx_pps, loss))
        if get_drop == False and loss < 0.001:
            logger.info(
                "." * 20 + "Tolerance drop && No drop in uut" + "." * 20)
            self.error_flag = False
            self.errors = {}

        self.tgen_NDR.clear_pkt_drop(uut=self.uut)
        return self.package_result(stats)

    def pre_test(self, mult=1000):
        self.astf_client.start(
            mult=mult, nc=True, latency_pps=0)
        self.astf_client.stop()
        self.astf_client.clear_stats()

        time.sleep(2)
        self.astf_client.start(
            mult=mult, nc=True, latency_pps=0)
        time.sleep(10)
        stats = self.astf_client.get_stats()
        self.astf_client.stop()
        self.error_flag, self.errors = self.astf_client.is_traffic_stats_error(stats[
            'traffic'])

        logger.info("error_flag:{} errors:{}".format(
            self.error_flag, self.errors))
        logger.info("{}".format(stats))

        rx_pps = stats['total']['rx_pps']
        tx_pps = stats['total']['tx_pps']
        loss = abs(float(rx_pps) - float(tx_pps)) / float(tx_pps)
        # assert loss < 0.0001 and self.error_flag == False, ("Pre test Failed!")
        assert loss < 0.0001, ("Pre test Failed!")
        logger.info("." * 20 + "Pre Test Pass" + "." * 20)

    def my_find_ndr(self):
        self.pre_test(200)
        self.perf_run_interval(high_bound=100, low_bound=0)
        logger.info(self.multi_list)
        self.measure_traffic_rate()


if __name__ == '__main__':
    MyASTFNdrBench(server='10.75.28.110')
