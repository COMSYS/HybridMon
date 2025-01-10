# vim: ts=4:sw=4:et

import socket
from ipaddress import ip_address

p4 = bfrt.hybridmon.pipe

class Host(object):
    def __init__(self, ip0, mac0, if0, ip1, mac1, if1):
        from ipaddress import ip_address
        mac_address = lambda s: int(s.replace(":", ""), 16)
        self.ip0 = ip_address(ip0)
        self.mac0 = mac_address(mac0)
        self.if0 = if0
        self.ip1 = ip_address(ip1)
        self.mac1 = mac_address(mac1)
        self.if1 = if1

# refer to addresses of relevant hosts more easily
# TODO: Replace dummy entries for src and dst
zero = Host("0.0.0.0",  "00:00:00:00:00:00", None, "0.0.0.0",  "00:00:00:00:00:00", None)
src = Host("10.0.0.1", "00:00:00:00:01:01", 100, "10.0.1.1", "00:00:00:00:01:02", 200)
dst = Host("10.0.0.2", "00:00:00:00:02:01", 100, "10.0.1.2", "00:00:00:00:02:02", 200)

controller_egress = dst.if1              # port where collector is reachable
recirculation = 196                      # port for recirculation
fwd_destination = zero.if0                # target of regular packets, for storage and evaluation
active_inputs = [src.if0]                # traffic from which ports should produce records?

# dummy routing entries
if fwd_destination is None:
    p4.Ingress.ipv4_lpm.add_with_drop(
        dst_addr=ip_address("0.0.0.0"),
        dst_addr_p_length=0)
    p4.Ingress.ipv6_lpm.add_with_drop(
        dst_addr=ip_address("::"),
        dst_addr_p_length=0)
else:
    p4.Ingress.ipv4_lpm.add_with_send(
        dst_addr=ip_address("0.0.0.0"),
        dst_addr_p_length=0,
        port=fwd_destination)
    p4.Ingress.ipv6_lpm.add_with_send(
        dst_addr=ip_address("::"),
        dst_addr_p_length=0,
        port=fwd_destination)

# recirculated packets should be sent to this port
p4.Ingress.ipfix_route.set_default_with_send(port=controller_egress)

# activate input ports (NoAction is fine, we only check match/miss)
for port in active_inputs:
    p4.Ingress.ipfix_filter.add_with_NoAction(ingress_port=port)

# record collector (and a source address - kernel might care about correct subnet/ARP for interface)
p4.Egress.address_data.add_with_set_addresses_v4(
    egress_port=controller_egress,
    mac_saddr=src.mac1,
    mac_daddr=dst.mac1,
    ip_saddr=src.ip1,
    ip_daddr=zero.ip1,
    sport=1234,
    dport=9996)
