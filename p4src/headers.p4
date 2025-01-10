// vim: ts=4:sw=4:et:syntax=c

//#define NO_SUBSAMPLE
//#define REPORT_FRAGMENTS

// bits of hash per stage (15 => 32K entries)
#define PRECISION_WIDTH 15
#define WIDTH_TIMES_STAGES 30

#include <core.p4>
#include <tna.p4>

// simple register storing 1 value of type S
#define REGISTER(S, N) Register<bit<S>, _>(1, 0) reg_ ## N; \
                       RegisterAction<bit<S>, _, bit<S>>(reg_ ## N) N
#define REGISTERS(S, N, W) Register<bit<S>, bit<W>>(1 << W, 0) reg_ ## N; \
                           RegisterAction<bit<S>, bit<W>, bit<S>>(reg_ ## N) N
#define APPLY(S) void apply(inout bit<S> register, out bit<S> result)

#define IGNORED_PKTGEN_BITS 48

const bit<4> TEMPLATE_INDEX_IPV4 = 4;
const bit<4> TEMPLATE_INDEX_IPV6 = 6;

// port where template and recirculation comes from (ignoring pipe)
const bit<7> PKTGEN_INDEX = 68;

const bit<16> ETHERTYPE_TPID    = 0x8100;
const bit<16> ETHERTYPE_IPV4    = 0x0800;
const bit<16> ETHERTYPE_IPV6    = 0x86DD;
const bit<16> ETHERTYPE_ARP    = 0x0806;
const bit<16> ETHERTYPE_CONTROL = 0x9000;

const bit<8> IPPROTO_UDP   = 0x11;
const bit<8> IPPROTO_TCP   = 0x06;
const bit<8> IPPROTO_ICMP  = 0x01;
const bit<8> IPPROTO_ICMP6 = 0x3A;

const bit<12> TCPFLAG_FIN = 0x01;
const bit<12> TCPFLAG_SYN = 0x02;
const bit<12> TCPFLAG_RST = 0x04;
const bit<12> TCPFLAG_PSH = 0x08;
const bit<12> TCPFLAG_ACK = 0x10;
const bit<12> TCPFLAG_URG = 0x20;

typedef bit<4> header_type_t;
typedef bit<4> header_info_t;
const header_type_t HEADER_TYPE_NONE                = 0x0;
const header_type_t HEADER_TYPE_MIRROR              = 0x1;
const header_type_t HEADER_TYPE_CONTROL             = 0x2;
const header_info_t HEADER_INFO_TEMPLATE            = 0xF;
const header_info_t HEADER_INFO_MIRROR_DROP         = 0xE;
const header_info_t HEADER_INFO_MIRROR_RECORD_FULL  = 0xD;
const header_info_t HEADER_INFO_MIRROR_RECORD_HEAVY = 0xC;
const header_info_t HEADER_INFO_MIRROR_REPLACED     = 0xB;

const MirrorId_t MIRROR_CONTROLLER  = 1;
const MirrorId_t MIRROR_RECIRCULATE = 2;

// to disable subsampling, just pretend that everything is unknown and not inserted
#ifdef NO_SUBSAMPLE
#define replace      mirror(MIRROR_CONTROLLER, HEADER_INFO_MIRROR_RECORD_FULL)
#define record_full  mirror(MIRROR_CONTROLLER, HEADER_INFO_MIRROR_RECORD_FULL)
#define record_heavy mirror(MIRROR_CONTROLLER, HEADER_INFO_MIRROR_RECORD_FULL)
#define drop_heavy   mirror(MIRROR_CONTROLLER, HEADER_INFO_MIRROR_RECORD_FULL)
#else
#define replace      mirror(MIRROR_RECIRCULATE, HEADER_INFO_MIRROR_REPLACED)
#define record_full  mirror(MIRROR_CONTROLLER,  HEADER_INFO_MIRROR_RECORD_FULL)
#define record_heavy mirror(MIRROR_CONTROLLER,  HEADER_INFO_MIRROR_RECORD_HEAVY)
#define drop_heavy   mirror(MIRROR_CONTROLLER,  HEADER_INFO_MIRROR_DROP)
#endif

struct ip_pair {
    bit<32> src;
    bit<32> dst;
}

// padding for recirculated packets
header pktgen_pad_h {
    bit<IGNORED_PKTGEN_BITS> pad;
}

// common header for mirroring and control packets (as lookahead)
header internal_header_h {
    header_type_t type;
    header_info_t info;
}

header mirror_metadata_h {
    header_type_t type;
    header_info_t info;
    bit<7>        pad1;
    PortId_t      ingress_port;
    bit<7>        pad2;
    PortId_t      egress_port;
    bit<6>        pad3;
    MirrorId_t    mirror_session;
    bit<48>       ingress_mac_tstamp;
    bit<48>       ingress_global_tstamp;
    bit<32>       estimate;
    bit<32>       min_flow;
    bit<2>        pad4;
    bit<WIDTH_TIMES_STAGES>       flow_hash;
}

// packets from control plane need to specify partial checksum of payload (i.e., IPFIX template) so we can update
header control_h {
    header_type_t type;
    header_info_t info;
    bit<4>        template_index;
    bit<3>        pad;
    PortId_t      egress_port;
    bit<16>       payload_checksum;
}

header ethernet_h {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ether_type;
}

header vlan_tag_h {
    bit<3>  pcp;
    bit<1>  cfi;
    bit<12> vid;
    bit<16> ether_type;
}

header eth_pad_h {
    bit<32> pad;
}

header arp_h {
    bit<48> src_mac;
    bit<32> src_ip;
    bit<48> dst_mac;
    bit<32> dst_ip;
}

header ipv4_h {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> len;
    bit<16> identification;
    bit<3>  flags;
    bit<13> frag_offset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdr_checksum;
    bit<32> src_addr;
    bit<32> dst_addr;
}

header ipv4_options_h {
    varbit<320> data;
}

header ipv6_h {
    bit<4>   version;
    bit<8>   tclass;
    bit<20>  flow;
    bit<16>  len;
    bit<8>   nexthdr;
    bit<8>   ttl;
    bit<128> src_addr;
    bit<128> dst_addr;
}

header ipv6_opt_hdr_h {
    bit<8>  nexthdr;
    bit<8>  opt_len;
    bit<48> payload;
}

// instead of varbit: every IPv6 option payloads are always x times 64 bit
header ipv6_opt_payload_h {
    bit<64> payload;
}

#define IPV6_OPT(N) ipv6_opt_hdr_h N ## _hdr; ipv6_opt_payload_h N ## _payload

// common for tcp/udp so we do not need to use control flow
header ports_h {
    bit<16> sport;
    bit<16> dport;
}

header udp_h {
    bit<16> len;
    bit<16> checksum;
}

header tcp_h {
    bit<32> seq;
    bit<32> ack;
    bit<4>  offset;
    bit<12> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urg;
}

header icmp_h {
    bit<8> type;
    bit<8> code;
    bit<16> checksum;
}

header ipfix_header_h {
    bit<16> version;
    bit<16> len;
    bit<32> tstamp;
    bit<32> seq;
    bit<32> obs_domain;
}

// additional header for template body
header ipfix_template_h {
    bit<16> set_id;
    bit<16> len;
    bit<16> template_id;
    bit<16> num_fields;
}

// header and payload of record packet (should match run_pd_rpc.py)
header ipfix_record_h {
    bit<16>  template_id;
    bit<16>  len;
    bit<32>  packetDeltaCount;         // 2
    bit<32>  flowStartSeconds;         // 150
    bit<16>  ingressInterface;         // 10
    bit<16>  egressInterface;          // 14
    bit<48>  sourceMacAddress;         // 56
    bit<48>  destinationMacAddress;    // 80
    bit<8>   protocolIdentifier;       // 4
    bit<16>  tcpControlBits;           // 6
    bit<32>  octetDeltaCount;          // 1
    bit<16>  sourceTransportPort;      // 7
    bit<16>  destinationTransportPort; // 11
    bit<32>  tcpSynTotalCount;          // 218
    bit<32>  tcpAckTotalCount;          // 222
    bit<32>  tcpSequenceNumber;         // 184
    bit<16>  tcpWindowSize;              // 186
    bit<8>   ipTTL;                     // 192
    bit<8>   isDNS;                     // 512 - extension
    bit<8>   DNSRequestType;            // 513 - extension
    bit<8>   DNSResponseCode;           // 514 - extension
    bit<16>  fragmentOffset;            // 88
    bit<32>  fragmentIdentification;    // 54
    bit<8>   fragmentFlags;              // 197
    bit<32>  httpRequestMethod;         // 459
    bit<64>  httpMessageVersion;         // 462
    //bit<96> httpRequestTarget;           // 461
    bit<24>  httpStatusCode;             // 457
    //bit<160> httpStatusMessage;          // 10 - Vermont extension
    bit<8>   isStartTls;               // 515 - extension
}

header ipfix_v4_data_h {
    bit<32>  sourceIPv4Address;        // 8
    bit<32>  destinationIPv4Address;   // 12
    //bit<16>  icmpTypeCodeIPv4;         // 32 -- instead include icmp type and code in destinationTransportPort as done by YAF
}

header ipfix_v6_data_h {
    bit<128> sourceIPv6Address;        // 27
    bit<128> destinationIPv6Address;   // 28
    //bit<16>  icmpTypeCodeIPv6;         // 139 -- instead include icmp type and code in destinationTransportPort as done by YAF
}

//http request: method, uri
header http_req_h {
    bit<32>  httpRequestMethod;
    //bit<8>   space1; // 8
    //bit<96> httpRequestTarget; // length is flexible... parse as much as we want and/or can
}

//http response: stat_msg, stat_code
header http_resp_h {
    bit<64> httpMessageVersion;
    bit<8>  space1;
    bit<24> httpStatusCode;
    //bit<8>  space2;
    //bit<160> httpStatusMessage;  //needs Vermont PEN // length is flexible... but no really required due to available status code
}

header dns_h {
    bit<16> id;
    bit<1> query;
    bit<4> opcode;
    bit<1> aa;
    bit<1> tc;
    bit<1> rd;
    bit<1> ra;
    bit<3> z;
    bit<4> rcode;
    bit<16> qdcount;
    bit<16> ancount;
    bit<16> nscount;
    bit<16> arcount;
}

// for parsing 8 byte where needed (e.g., to identify starttls)
header data_8b_h {
    bit<64> data;
}
