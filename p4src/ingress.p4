// vim: ts=4:sw=4:et:syntax=c

const int IPV4_HOST_SIZE    = 8192;
const int IPV6_HOST_SIZE    = 8192;
const int IPV4_LPM_SIZE     = 4096;
const int IPV6_LPM_SIZE     = 4096;
const int MIRROR_SIZE       = 1024;
const int IPFIX_ROUTE_SIZE  = 16;
const int IPFIX_FILTER_SIZE = 128;
const int IDS_FILTER_SIZE = 1024;

const bit<3> DEPARSER_MIRROR = 0x3;

struct ingress_headers_t {
    control_h         ctrl;
    mirror_metadata_h mirror;
    ethernet_h        ethernet;
    vlan_tag_h        vlan_tag;
    ipv4_h            ipv4;
    ipv4_options_h    ipv4_options;
    ipv6_h            ipv6;
    IPV6_OPT         (ipv6_opt_1);
    ports_h           ports;
    tcp_h             tcp;
    udp_h             udp;
    icmp_h            icmp;
    http_req_h        http_req;
    http_resp_h       http_resp;
    arp_h             arp;
}

struct ingress_meta_t {
    header_type_t mirror_header_type;
    header_info_t mirror_header_info;
    PortId_t      ingress_port;
    PortId_t      egress_port;
    MirrorId_t    mirror_session;
    bit<48>       ingress_mac_tstamp;
    bit<48>       ingress_global_tstamp;
    bit<WIDTH_TIMES_STAGES>       flow_hash;
    bit<1>        template_ok;
    bit<6>        flow_match;
    bit<32>       estimate;
    bit<32>       min_flow;
    bit<32>       random_large;
    bit<12>       random_small;
    bit<32>       ipv6_src_low;
    bit<32>       ipv6_dst_low;
    bit<32>       ipv6_hash;
}

parser IngressParser(    packet_in                    pkt,
                     out ingress_headers_t            hdr,
                     out ingress_meta_t               meta,
                     out ingress_intrinsic_metadata_t ig_intr_md)
{
    internal_header_h internal;

    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        // meta data for decision making w.r.t subsampling and record generation
        meta.estimate = 0;
        meta.min_flow = 0;
        transition select(ig_intr_md.ingress_port[6:0]) {
            PKTGEN_INDEX: parse_pktgen;
            default     : parse_ethernet;
        }
    }

    state parse_pktgen {
        // check if control packet or recirculated mirror packet
        pkt.advance(IGNORED_PKTGEN_BITS);
        internal = pkt.lookahead<internal_header_h>();

        transition select(internal.type, internal.info) {
            (HEADER_TYPE_CONTROL, _): parse_control;
            (HEADER_TYPE_MIRROR , _): parse_mirror;
            default                 : reject;
        }
    }

    state parse_control {
        pkt.extract(hdr.ctrl);
        transition accept;
    }

    state parse_mirror {
        pkt.extract(hdr.mirror);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_TPID   : parse_vlan_tag;
            ETHERTYPE_IPV4   : parse_ipv4;
            ETHERTYPE_IPV6   : parse_ipv6;
            ETHERTYPE_ARP    : parse_arp;
            ETHERTYPE_CONTROL: parse_control;
            default          : accept;
        }
    }

    state parse_vlan_tag {
        pkt.extract(hdr.vlan_tag);
        transition select(hdr.vlan_tag.ether_type) {
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_IPV6: parse_ipv6;
            ETHERTYPE_ARP    : parse_arp;
            default       : accept;
        }
    }

    state parse_arp {
        //advance to source/destination addresses as we are not interested in the previous fields
        pkt.advance(64);
        pkt.extract(hdr.arp);
        transition accept;
    }

    /* parse IPv4 header and options if available, then upper layer protocol */
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.ihl) {
            5: parse_ipv4_no_options;
            6..15: parse_ipv4_options;
        }
    }

    // parse ipv4 options with varbit
    state parse_ipv4_options {
        pkt.extract(
            hdr.ipv4_options,
            (bit<32>)(hdr.ipv4.ihl - 5) * 32);
        transition parse_ipv4_no_options;
    }

    // no (more) options to parse
    state parse_ipv4_no_options {
        transition select(hdr.ipv4.frag_offset) {
            0: parse_upper_layer;
            default: accept;
        }
    }

    /* if IPv4 parsed, transition to upper layer protocol (tcp, udp, or icmp supported) */
    state parse_upper_layer {
        transition select(hdr.ipv4.protocol) {
            IPPROTO_TCP: parse_tcp_ports;
            IPPROTO_UDP: parse_udp;
            IPPROTO_ICMP: parse_icmp;
            default          : accept;
        }
    }

    /* if parse IPv6, parse IPv6 header without options (as currently not supported),
    then transition to upper layer protocol (udp, tcp, or icmp) */
    state parse_ipv6 {
        pkt.extract(hdr.ipv6);
        transition select(hdr.ipv6.nexthdr) {
            IPPROTO_TCP  : parse_tcp_ports;
            IPPROTO_UDP  : parse_udp;
            IPPROTO_ICMP6: parse_icmp;
            default      : accept;
        }
    }

    /* parse icmp */
    state parse_icmp {
        pkt.extract(hdr.icmp);
        transition accept;
    }

    /* parse udp ports and remaining udp header information,
    then transition to potential application layer fields */
    state parse_udp {
        pkt.extract(hdr.ports);
        pkt.extract(hdr.udp);
        hdr.icmp.type = 0;
        hdr.icmp.code = 0;
        transition parse_application;
    }

    // http on top of udp (if using ports 80 and 8080)
    state parse_application {
        transition select(hdr.ports.sport, hdr.ports.dport) {
            (80, _): parse_http_resp;
            (_, 80): parse_http_req;
            (8080, _): parse_http_resp;
            (_, 8080): parse_http_req;
            default: accept;
        }
    }

    /* parse tcp ports and detect if http is present (if using ports 80 and 8080),
    then parse either remaining tcp header and options PLUS http, or the remaining tcp header only */
    state parse_tcp_ports {
        pkt.extract(hdr.ports);
        hdr.icmp.type = 0;
        hdr.icmp.code = 0;
        transition select(hdr.ports.sport, hdr.ports.dport) {
            (80, _): parse_tcp_and_http_resp;
            (_, 80): parse_tcp_and_http_req;
            (8080, _): parse_tcp_and_http_resp;
            (_, 8080): parse_tcp_and_http_req;
            default: parse_tcp;
        }
    }

    // parse the remaining tcp header and accept (no tcp options or application parsing required)
    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }

    // parse the remaining tcp header and options to access http request fields
    state parse_tcp_and_http_req {
        pkt.extract(hdr.tcp);
        // TCP options are 0..10 words of 4 bytes, i.e., 0..40 bytes need to be skipped
        transition select(hdr.tcp.offset) {
            5: parse_tcp_no_options_http_req;
            6: skip_4_http_req;
            7: skip_8_http_req;
            8: skip_12_http_req;
            9: skip_16_http_req;
            default: parse_tcp_opt_more_http_req;
        }
    }

    // parse more TCP options
    state parse_tcp_opt_more_http_req {
        pkt.advance(160);
        transition select(hdr.tcp.offset) {
            10: parse_tcp_no_options_http_req;
            11: skip_4_http_req;
            12: skip_8_http_req;
            13: skip_12_http_req;
            14: skip_16_http_req;
            15: skip_20_http_req;
            default: reject;
        }
    }

    // no (more) options to parse
    state parse_tcp_no_options_http_req {
        transition parse_http_req;
    }

    // advance states
    state skip_4_http_req {
        pkt.advance(32 * 1);
        transition parse_tcp_no_options_http_req;
    }

    state skip_8_http_req {
        pkt.advance(32 * 2);
        transition parse_tcp_no_options_http_req;
    }

    state skip_12_http_req {
        pkt.advance(32 * 3);
        transition parse_tcp_no_options_http_req;
    }

    state skip_16_http_req {
        pkt.advance(32 * 4);
        transition parse_tcp_no_options_http_req;
    }

    state skip_20_http_req {
        pkt.advance(32 * 5);
        transition parse_tcp_no_options_http_req;
    }

    // parse the remaining tcp header and options to access http response fields
    state parse_tcp_and_http_resp {
        pkt.extract(hdr.tcp);
        // TCP options are 0..10 words of 4 bytes, i.e., 0..40 bytes need to be skipped
        transition select(hdr.tcp.offset) {
            5: parse_tcp_no_options_http_resp;
            6: skip_4_http_resp;
            7: skip_8_http_resp;
            8: skip_12_http_resp;
            9: skip_16_http_resp;
            default: parse_tcp_opt_more_http_resp;
        }
    }

    // parse more TCP options
    state parse_tcp_opt_more_http_resp {
        pkt.advance(160);
        transition select(hdr.tcp.offset) {
            10: parse_tcp_no_options_http_resp;
            11: skip_4_http_resp;
            12: skip_8_http_resp;
            13: skip_12_http_resp;
            14: skip_16_http_resp;
            15: skip_20_http_resp;
            default: reject;
        }
    }

    // no (more) options to parse
    state parse_tcp_no_options_http_resp {
        transition parse_http_resp;
    }

    // advance states
    state skip_4_http_resp {
        pkt.advance(32 * 1);
        transition parse_tcp_no_options_http_resp;
    }

    state skip_8_http_resp {
        pkt.advance(32 * 2);
        transition parse_tcp_no_options_http_resp;
    }

    state skip_12_http_resp {
        pkt.advance(32 * 3);
        transition parse_tcp_no_options_http_resp;
    }

    state skip_16_http_resp {
        pkt.advance(32 * 4);
        transition parse_tcp_no_options_http_resp;
    }

    state skip_20_http_resp {
        pkt.advance(32 * 5);
        transition parse_tcp_no_options_http_resp;
    }

    // parse http request fields
    state parse_http_req {
        pkt.extract(hdr.http_req);
        transition accept;
    }

    // parse http response fields
    state parse_http_resp {
        pkt.extract(hdr.http_resp);
        transition accept;
    }
}

control Ingress(inout ingress_headers_t                         hdr,
                inout ingress_meta_t                            meta,
                in    ingress_intrinsic_metadata_t              ig_intr_md,
                in    ingress_intrinsic_metadata_from_parser_t  ig_prsr_md,
                inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                inout ingress_intrinsic_metadata_for_tm_t       ig_tm_md)
{

    Counter<bit<64>, bit<2>>(4, CounterType_t.PACKETS) recirc_packet_stats;

    // action to send packet to a given port
    action send(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
        meta.egress_port = port;
    }

    // action to drop packet
    action drop() {
        ig_dprsr_md.drop_ctl = 1;
        meta.egress_port = 0;
    }


    table ipv4_host {
        key = { hdr.ipv4.dst_addr : exact; }
        actions = { send; drop; @defaultonly NoAction; }
        const default_action = NoAction();
        size = IPV4_HOST_SIZE;
    }

    table ipv6_host {
        key = { hdr.ipv6.dst_addr : exact; }
        actions = { send; drop; @defaultonly NoAction; }
        const default_action = NoAction();
        size = IPV6_HOST_SIZE;
    }

    table ipv4_lpm {
        key = { hdr.ipv4.dst_addr : lpm; }
        actions = { send; drop; }
        const default_action = send(64);
        size = IPV4_LPM_SIZE;
    }

    table ipv6_lpm {
        key = { hdr.ipv6.dst_addr : lpm; }
        actions = { send; drop; }
        const default_action = send(64);
        size = IPV6_LPM_SIZE;
    }

    // simply send the packet (i.e., the record which is crafted from it) to the collector port
    table ipfix_route {
        key = { }
        actions = { send; @defaultonly NoAction; }
        default_action = NoAction;
        size = IPFIX_ROUTE_SIZE;
    }

    /* decide whether to consider the packet for monitoring;
    to define by administrator to exclude generally uninteresting traffic
    (include match on other fields if necessary) */
    table ipfix_filter {
        key = { ig_intr_md.ingress_port: exact; }
        actions = { NoAction; }
        default_action = NoAction();
        size = IPFIX_FILTER_SIZE;
    }

    /* decide whether to consider the packet for monitoring; 
    e.g., temporary rules set by IDS */
    table ids_filter {
        key = {
            hdr.ethernet.src_addr : exact;
            /*hdr.ipv4.src_addr : exact;
            hdr.ipv4.dst_addr : exact;
            hdr.ports.dport : exact; */
        }
        actions = { NoAction; }
        default_action = NoAction();
        size = IDS_FILTER_SIZE;
    }

    // activate specified mirror session defined in run_pd_rpc.py (mirror from ingress to egress)
    action mirror(MirrorId_t mirror_session, header_info_t info) {
        ig_dprsr_md.mirror_type    = DEPARSER_MIRROR;
        meta.mirror_header_type    = HEADER_TYPE_MIRROR;
        meta.mirror_header_info    = info;
        meta.ingress_port          = ig_intr_md.ingress_port;
        meta.mirror_session        = mirror_session;
        meta.ingress_mac_tstamp    = ig_intr_md.ingress_mac_tstamp;
        meta.ingress_global_tstamp = ig_prsr_md.global_tstamp;
    }

    // table for decision making w.r.t subsampling _and_ probabilistic recirculation (decision is submitted to the egress using the mirror header)
    table ipfix_mirror {
        key = {
            meta.estimate : ternary;
            meta.min_flow : ternary;
            meta.random_large : ternary;
            meta.random_small : range;
        }
        actions = { mirror; }
        const default_action = record_full;
        size = MIRROR_SIZE;
        const entries = {
#include "mirror_entries.p4"
        }
    }

    PRECISION_REGS(PRECISION_WIDTH, 1);
    PRECISION_REGS(PRECISION_WIDTH, 2);

    // store if an IPFIX template was seen
    Register<bit<1>, bit<1>>(2) templates_seen;
    RegisterAction<bit<1>, bit<1>, bit<1>>(templates_seen) register_template = {
        void apply(inout bit<1> register, out bit<1> result) {
            register = 1;
        }
    };
    RegisterAction<bit<1>, bit<1>, bit<1>>(templates_seen) has_template = {
        void apply(inout bit<1> register, out bit<1> result) {
            result = register;
        }
    };

    // define hashes
    Hash<bit<32>>(HashAlgorithm_t.CRC32) crc32;
    Hash<bit<32>>(HashAlgorithm_t.CRC32) ipv6_hash;
    Random<bit<32>>() random_large;
    Random<bit<12>>() random_small;

    bit<PRECISION_WIDTH> ix1;
    bit<PRECISION_WIDTH> ix2;
    
    
    action start_ingress() {
        meta.ipv6_src_low = hdr.ipv6.src_addr[31:0];
        meta.ipv6_dst_low = hdr.ipv6.dst_addr[31:0];
        
        // indexes into hashmap
        meta.flow_hash = crc32.get({
            hdr.ipv4.src_addr,
            hdr.ipv4.dst_addr,
            hdr.ipv6.src_addr,
            hdr.ipv6.dst_addr,
            hdr.ports.sport,
            hdr.ports.dport,
            hdr.icmp.type,
            hdr.icmp.code
        })[2*PRECISION_WIDTH-1:0];
    }

    action register_template_0() {
        register_template.execute(0);
    }

    action register_template_1() {
        register_template.execute(1);
    }

    action meta_ipv6_hash() {
        // only lower 32 bit of IPv6 are compared; others are hashed
        meta.ipv6_hash = ipv6_hash.get({
                3w5,
                hdr.ipv6.dst_addr[127:32],
                4w11,
                hdr.ipv6.src_addr[127:32],
                1w1
            });
        hdr.mirror.estimate = hdr.mirror.min_flow - 4;
    }

    apply {
        start_ingress();

        ix1 = meta.flow_hash[PRECISION_WIDTH-1:0];
        ix2 = meta.flow_hash[2*PRECISION_WIDTH-1:PRECISION_WIDTH];

        // if control packet
        if (hdr.ctrl.isValid()) {
            if (hdr.ctrl.info == HEADER_INFO_TEMPLATE) {
                if (hdr.ctrl.template_index == TEMPLATE_INDEX_IPV4) {
                    register_template_0();
                } else {
                    register_template_1();
                }
                send(hdr.ctrl.egress_port);
            }
        // if mirrored packet
        } else if (hdr.mirror.isValid()) {
            if (hdr.mirror.min_flow[1:0] == 1) {
                precision_upd_1_ports.execute(ix1);
                precision_upd_1_icmp.execute(ix1);
                precision_upd_1_ipv4.execute(ix1);
                precision_upd_1_ipv6.execute(ix1);
                precision_upd_1_ipv6_hash.execute(ix1);
                precision_est_1_write.execute(ix1);
            } else if (hdr.mirror.min_flow[1:0] == 2) {
                precision_upd_2_ports.execute(ix2);
                precision_upd_2_icmp.execute(ix2);
                precision_upd_2_ipv4.execute(ix2);
                precision_upd_2_ipv6.execute(ix2);
                precision_upd_2_ipv6_hash.execute(ix2);
                precision_est_2_write.execute(ix2);
            }

            ipfix_route.apply();
        // original packet (not processed further)
        } else {
            ig_tm_md.bypass_egress = 1;

            meta.random_large = random_large.get();
            meta.random_small = random_small.get();
            
            // only lower 32 bit of IPv6 are compared; others are hashed
            bit template_ok_index = 0;
            if (hdr.ipv4.isValid()) {
                if (!ipv4_host.apply().hit) {
                    ipv4_lpm.apply();
                }
                meta.flow_match[1:1] = precision_cmp_1_ipv4.execute(ix1);
                meta.flow_match[2:2] = 1;
                meta.flow_match[4:4] = precision_cmp_2_ipv4.execute(ix2);
                meta.flow_match[5:5] = 1;
            } else if (hdr.ipv6.isValid()) {
                if (!ipv6_host.apply().hit) {
                    ipv6_lpm.apply();
                }
                template_ok_index = 1;
                meta.flow_match[1:1] = precision_cmp_1_ipv6.execute(ix1);
                meta.flow_match[2:2] = precision_cmp_1_ipv6_hash.execute(ix1);
                meta.flow_match[4:4] = precision_cmp_2_ipv6.execute(ix2);
                meta.flow_match[5:5] = precision_cmp_2_ipv6_hash.execute(ix2);
            } 
            meta.template_ok = has_template.execute(template_ok_index);

            if (ipfix_filter.apply().hit) {
                if (!ids_filter.apply().hit) {
                    if (meta.template_ok == 1 && (hdr.ports.isValid() || hdr.icmp.isValid())) {
                        if (hdr.ports.isValid()) {
                            meta.flow_match[0:0] = precision_cmp_1_ports.execute(ix1);
                            meta.flow_match[3:3] = precision_cmp_2_ports.execute(ix2);
                        } else {
                            meta.flow_match[0:0] = precision_cmp_1_icmp.execute(ix1);
                            meta.flow_match[3:3] = precision_cmp_2_icmp.execute(ix2);
                        }

                        if (meta.flow_match[2:0] == 3w7) {

                            if (hdr.tcp.isValid() && hdr.tcp.flags & (TCPFLAG_RST | TCPFLAG_FIN) != 0) {
                                meta.estimate = 1;
                                precision_est_1_reset.execute(ix1);
                                record_heavy;
                            } else {
                                meta.estimate = precision_est_1_inc.execute(ix1);

                                // recirculation, subsampling
                                ipfix_mirror.apply();
                            }

                        } else if (meta.flow_match[5:3] == 3w7) {

                            if (hdr.tcp.isValid() && hdr.tcp.flags & (TCPFLAG_RST | TCPFLAG_FIN) != 0) {
                                meta.estimate = 2;
                                precision_est_2_reset.execute(ix2);
                                record_heavy;
                            } else{
                                meta.estimate = precision_est_2_inc.execute(ix2);

                                // recirculation, subsampling
                                ipfix_mirror.apply();
                            }
                        } else {
                            if (hdr.tcp.isValid() && hdr.tcp.flags & (TCPFLAG_RST | TCPFLAG_FIN) != 0) {
                                record_full;
                            } else {
                                // no match, could replace entry with lower flow size
                                bit<32> flow_entry1;
                                bit<32> flow_entry2;
                                flow_entry1 = precision_est_1_size.execute(ix1);
                                flow_entry2 = precision_est_2_size.execute(ix2);
                                // 32:min_flow = (30:flowsize, 2:stage) => min automatically chooses (and remembers) stage
                                meta.min_flow = min(flow_entry1, flow_entry2);

                                // recirculation, subsampling
                                ipfix_mirror.apply();
                            }
                        }
                        
                        
                    } else if (meta.template_ok == 1) {
    #ifdef REPORT_FRAGMENTS
                        if (hdr.ipv4.frag_offset != 0 || hdr.ipv4.frag_offset == 0) {
    #else
                        if (!hdr.ipv4.isValid() || hdr.ipv4.frag_offset == 0) {
    #endif
                            // no TCP/UDP/ICMP info, always report
                            record_full;
                        }
                    }
                }
            }
        }

        if (meta.mirror_session == MIRROR_RECIRCULATE) {
            recirc_packet_stats.count(1);
        } else {
            recirc_packet_stats.count(0);
        }

    }
}

control IngressDeparser(      packet_out                                pkt,
                        inout ingress_headers_t                         hdr,
                        in    ingress_meta_t                            meta,
                        in    ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md)
{
    Mirror() mirror;

    apply {
        if (ig_dprsr_md.mirror_type == DEPARSER_MIRROR) {
            mirror.emit<mirror_metadata_h>(meta.mirror_session, {
                meta.mirror_header_type,
                meta.mirror_header_info,
                0,
                meta.ingress_port,
                0,
                meta.egress_port,
                0,
                meta.mirror_session,
                meta.ingress_mac_tstamp,
                meta.ingress_global_tstamp,
                meta.estimate,
                meta.min_flow,
                0,
                meta.flow_hash
            });
        }

        pkt.emit(hdr);
    }
}
