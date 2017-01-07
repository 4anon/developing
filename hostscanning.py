
def hostscan():
    from scapy.all import *
    import os
    gateway_ip = os.popen("/sbin/ip route | awk '/default/ { printf $3 }'").read()
    ans,unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=str(gateway_ip)),timeout=2, verbose = 0)
    ans.summary(lambda (s,r): r.sprintf("[+]You did find: " + "[*]IP: %ARP.psrc% [*]MAC: %Ether.src% "))
