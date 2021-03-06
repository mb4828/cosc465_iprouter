COSC465 IP router projects
==========================
Computer Networking

 * <b>Project 3</b>: Implement functionality to respond to ARP requests for interfaces assigned on the router
 * <b>Project 4</b>: Receive and forward IP packets destined for other hosts using "longest prefix match" look-ups and make ARP requests for packets that have no known MAC address
 * <b>Project 5</b>: Respond to ICMP messages (e.g. pings) and generate ICMP errors when necessary (e.g. TTL expired, network/host/port unreachable)

====
<b>Further Documentation:</b>


This repo contains starter files and scripts for a series of projects for building an IP router in Python.

Three key files:
 * `setup.sh`: a script to setup a directory for running SRPy tests and "real" mininet experiments
 * `setup2.sh`: a script to setup components for project 4
 * `setup3.sh`: a script to setup components for project 5
 * `start_mininet.py`: a script to build a Mininet topology for running experiments.

Any .srpy files contain serialized test case code.

Documentation:

 * [SRPY documentation](https://docs.google.com/document/d/1ZT8jKr1vDWsSg12Bf63qcKMxyncIVJGwTLCUY140tWg/edit?usp=sharing)
 * [POX packet library documentation](https://docs.google.com/document/d/1d3Sn8B1arx8sZOZszcEwx1SWIVBvKyCDAKJOAQOlAtc/edit?usp=sharing)

See [Mininet documentation](http://www.mininet.org) and [POX documentation](https://openflow.stanford.edu/display/ONL/POX+Wiki) for additional reference material.

----

I gratefully acknowledge support from the NSF.  The materials here are
based upon work supported by the National Science Foundation under
grant CNS-1054985 ("CAREER: Expanding the functionality of Internet
routers").

Any opinions, findings, and conclusions or recommendations expressed
in this material are those of the author and do not necessarily
reflect the views of the National Science Foundation.
