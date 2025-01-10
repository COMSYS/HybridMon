# vim: ts=4:sw=4:et
from __future__ import print_function

from scapy.all import *
import time
import socket
import codecs
from itertools import chain

# set packet destinations
# ports should match bfrt_setup.py
controller_egress = 53
recirculation = 196

# begin constructing a complete IPFIX template packet
ipfix_version = 10
ipfix_seq = 0
ipfix_obs = 0
ipfix_set_template = 2
ipfix_template_id = 256

# fields that will be extracted, announced in template (should match headers.p4)
ipfix_fields = [
    (2, 4), # packetDeltaCount // reduced-size encoding
    (150, 4), # flowStartSeconds
    (10, 2), # ingressInterface // reduced-size encoding
    (14, 2), # egressInterface // reduced-size encoding
    (56, 6), # sourceMacAddress
    (80, 6), # destinationMacAddress
    (4, 1), # protocolIdentifier
    (6, 2), # tcpControlFlags
    (1, 4), # octetDeltaCount // reduced-size encoding
    (7, 2), # sourceTransportPort
    (11, 2), # destinationTransportPort  // contains ICMP type * 256 + ICMP code for ICMP flows (yaf issue)
    (218, 4), #tcpSynTotalCount //reduced-size encoding
    (222, 4), #tcpAckTotalCount //reduced-size encoding
    (184, 4), #tcpSequenceNumber
    (186, 2), #tcpWindowSize
    (192, 1), #ipTTL
    ((1 << 15) | 512, 1),#custom extension - isDNS
    (0, 5540), #RWTH PEN
    ((1 << 15) | 513, 1),#custom extension - DNS request type (query or response)
    (0, 5540), #RWTH PEN
    ((1 << 15) | 514, 1),#custom extension - DNS response code
    (0, 5540), #RWTH PEN
    (88, 2), # fragment offset
    (54, 4), # fragment identification
    (197, 1), #fragment flags
    (459, 4), #httpRequestMethod
    (462, 8), # httpMessageVersion
    #(461, 12), #httpRequestTarget -- length is variable
    (457, 3), #httpStatusCode,
    #((1 << 15) | 10, 20), #httpStatusPhrase -- length is variable
    #(0, 19518) #use TUM PEN and change the definition to it in FIXIDS
    ((1 << 15) | 515, 1),#custom extension - start
    (0, 5540), #RWTH PEN
]

ipfix_v4_fields = [
    (8, 4), # sourceIPv4Address
    (12, 4), # destinationIPv4Address
    #(32, 2), # icmpTypeCodeIPv4 -- instead include icmp type and code in destinationTransportPort as done by YAF
]

ipfix_v6_fields = [
    (27, 16), # sourceIPv6Address
    (28, 16), # destinationIPv6Address
    #(139, 2), # icmpTypeCodeIPv6 -- -- instead include icmp type and code in destinationTransportPort as done by YAF
]

def build_payload(id, fields):
    ipfix_header = struct.pack("!HHLLLHHHH",
        ipfix_version,
        24 + 4 * len(fields),                  # size[ipfix hdr|template hdr|template]
        int(time.time()),                      # reference timestamp, in seconds
        ipfix_seq,                             # will be set by tofino anyway
        ipfix_obs,
        ipfix_set_template,
        8 + 4 * len(fields),                   # size[template hdr|template]
        ipfix_template_id | id,                # id should distinguish IPv4/IPv6/other templates
        len(fields) - sum(field >> 15 for (field, length) in fields)
                                               # number of fields, corrected for any org-specific fields (which require two half-words)
    )
    ipfix_template = b"".join(struct.pack("!HH", field, length) for (field, length) in fields)
    return ipfix_header, ipfix_template

def build_template_packet(id, extra_fields):
    print("build_template_packet at "+str(int(time.time())))
    header, template = build_payload(id, ipfix_fields + extra_fields)
    p = struct.pack("!BHH",
        0x2f,                                  # type:control | info:template
        (id << 12) | controller_egress,        # template_id  | target_egress
        0xffff ^ checksum(template)            # partial checksum, switch incrementally adds network headers
    ) + header + template
    return p

max_mirror_length = 256 # should contain Eth + Dot1Q + {IPv4+Opt, IPv6} + {TCP, UDP}

# Setup mirroring to collector and to recirculation
print("Mirror destination 1, sending to port", controller_egress)
mirror.session_create(mirror.MirrorSessionInfo_t(
    mir_type=mirror.MirrorType_e.PD_MIRROR_TYPE_NORM,
    direction=mirror.Direction_e.PD_DIR_BOTH,
    mir_id=1,
    egr_port=controller_egress,
    egr_port_v=True,
    max_pkt_len=max_mirror_length))


print("Mirror destination 2, recirculate to port", recirculation)
mirror.session_create(mirror.MirrorSessionInfo_t(
    mir_type=mirror.MirrorType_e.PD_MIRROR_TYPE_NORM,
    direction=mirror.Direction_e.PD_DIR_BOTH,
    mir_id=2,
    egr_port=recirculation,
    egr_port_v=True,
    max_pkt_len=max_mirror_length))

print("Sending template packet periodically every 4 seconds")
pktgen.enable(recirculation)

# build packets once to get their sizes
p4 = build_template_packet(4, ipfix_v4_fields)
p6 = build_template_packet(6, ipfix_v6_fields)

cfg4 = pktgen.app_cfg_init()
cfg4.length = len(p4)
cfg4.trigger_type = pktgen.TriggerType_t.TIMER_PERIODIC
cfg4.timer = hex_to_i32(0xFFFFFFFF)
cfg6 = pktgen.app_cfg_init()
cfg6.length = len(p6)
cfg6.buffer_offset = (len(p4) + 15) & ~15
cfg6.trigger_type = pktgen.TriggerType_t.TIMER_PERIODIC
cfg6.timer = hex_to_i32(0xFFFFFFFF)
def write_pkt_buffer_event():
    p4 = build_template_packet(4, ipfix_v4_fields)
    p6 = build_template_packet(6, ipfix_v6_fields)
    align = ((len(p4) + 15) & ~15) - len(p4)
    buf = p4 + b'\x00' * align + p6
    print(buf)
    pktgen.write_pkt_buffer(0, len(buf), buf)
    threading.Timer(1, write_pkt_buffer_event).start()
write_pkt_buffer_event()
pktgen.cfg_app(0, cfg4)
pktgen.app_enable(0)
pktgen.cfg_app(1, cfg6)
pktgen.app_enable(1)
conn_mgr.complete_operations()

