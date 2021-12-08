There are many traffic generators (free and business) in communications industry, such IXIA,Sprint,TRex. IXIA and Sprint is mainly target to L2/L3 layer in ISO model. TRex is a free open source project sponsored by Cisco, it support multi-mode (STL/STF/ASTF) to support L2/L3/L4 layer measurment.
Internet accrossed application is usually TCP-based. The purpose of Application Performance monitor is to quantify QoE (Quality of user Experience).Neither IXIA nor Sprint is suitable in such scenairios. TRex not either! Why?  TRex is DPDK based high performance traffic generator (reach 100Gbps), it rebuild TCP stack based on RPC standard (but maybe not latest, not mainstream), it can only represent one TCP model, may not full. If you are familer with operation system, you will know that TCP/IP stack is inside kernel,so we will not usually upgrade kernel, you can't say there is no update in OS release. Beside that, there are support system level  APIs to change TCP/IP stack parameters，such as retreansmit algorithom. Another tricky problem is that there are so many different types of end-point device, maybe it is a Windows PC, an Android Smartphone.... They may common TCP/IP stack with some mortal wisdom. So what I  believe is when you need measure network releated  parameters for Application, leverage system's TCP/IP stack. You can cover differenet endpoint device (both server and client)

This tool will have some scale and pressure, but you need high network stress,this project is not suitable to you.

Scale num measured:

5000 TCP connection/second
150Mpbps  bir-directionl througput

U5#show plat hard qfp ac data u summary 
  CPP 0:                     5 secs        1 min        5 min       60 min
Input:     Total (pps)        25261         5604         1135          110
                 (bps)    161924000     36827072      7376616       626608
Output:    Total (pps)        25250         5592         1120           96
                 (bps)    161935344     36832168      7379488       637040
Processing: Load (pct)           17            7            4            3


client/server: 

![屏幕快照 2021-12-08 11 54 55 AM](https://user-images.githubusercontent.com/28484663/145145581-8e77f72e-f703-46af-938b-11437f7698db.png)
