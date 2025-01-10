// vim: ts=4:sw=4:et:syntax=c

const int COLL_ADDR_SIZE = 512;

#define HASH(C) (hdr.mirror.flow_hash[C*PRECISION_WIDTH-1:(C-1)*PRECISION_WIDTH])

struct egress_headers_t {
    // headers of incoming packet
    pktgen_pad_h      ctrl_pad;
    mirror_metadata_h mirror;
    ethernet_h        ethernet;
    vlan_tag_h        vlan_tag;
    ipv4_h            ipv4;
    ipv6_h            ipv6;
    ports_h           ports;
    tcp_h             tcp;
    udp_h             udp;
    icmp_h            icmp;
    dns_h             dns;
    http_req_h        http_req;
    http_resp_h       http_resp;
    arp_h             arp;

    // new headers for path to collector
    ipv4_h            r_ipv4;
    ipv6_h            r_ipv6;
    ports_h           r_ports;
    udp_h             r_udp;
    ipfix_header_h    ipfix;
    ipfix_template_h  template;
    ipfix_record_h    record;
    ipfix_v4_data_h   datav4;
    ipfix_v6_data_h   datav6;
    eth_pad_h         pad;
}

struct egress_meta_t {
    control_h ctrl;
    bit<16>   total_len;
    bit<16>   csum_len;
    bit<32>   tstamp_inc;
    bit<8>    isDNS;
    data_8b_h data_start;
}

parser EgressParser(    packet_in                   pkt,
                    out egress_headers_t            hdr,
                    out egress_meta_t               meta,
                    out egress_intrinsic_metadata_t eg_intr_md)
{
    internal_header_h internal;
    ipv6_opt_hdr_h ipv6_opt_hdr;

    state start {
        pkt.extract(eg_intr_md);
        // all packets have an internal_header; either mirror metadata or control packet
        internal = pkt.lookahead<internal_header_h>();

        transition select(internal.type, internal.info) {
            (HEADER_TYPE_CONTROL, _): parse_control;
            (HEADER_TYPE_MIRROR , _): parse_mirror;
            default                 : reject;
        }
    }

    state parse_control {
        pkt.extract(meta.ctrl);
        transition select(meta.ctrl.info) {
            HEADER_INFO_TEMPLATE: parse_template;
            default             : reject;
        }
    }

    state parse_template {
        pkt.extract(hdr.ipfix);
        pkt.extract(hdr.template);
        transition accept;
    }

    state parse_mirror {
        pkt.extract(hdr.mirror);
        transition select(eg_intr_md.egress_port[6:0]) {
            PKTGEN_INDEX: accept;
            default     : parse_ethernet;
        }
    }

    state parse_ethernet {
        // prepare IPFIX header information here
        hdr.ipfix.setValid();
        hdr.ipfix.version = 0x000A;
        hdr.ipfix.tstamp = 0;
        hdr.ipfix.obs_domain = 0;

        hdr.record.setValid();
        hdr.record.sourceMacAddress = hdr.ethernet.src_addr;
        hdr.record.destinationMacAddress = hdr.ethernet.dst_addr;
        hdr.record.flowStartSeconds = 0;

        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_TPID: parse_vlan_tag;
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_IPV6: parse_ipv6;
            ETHERTYPE_ARP:  parse_arp;
            default       : consume_payload;
        }
    }

    state parse_vlan_tag {
        pkt.extract(hdr.vlan_tag);
        transition select(hdr.vlan_tag.ether_type) {
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_IPV6: parse_ipv6;
            ETHERTYPE_ARP:  parse_arp;
            default       : consume_payload;
        }
    }

    state parse_arp {
        pkt.advance(64);
        pkt.extract(hdr.arp);
        transition consume_payload;
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.ihl) {
            5: parse_ipv4_opt_0;
            6: parse_ipv4_opt_1;
            7: parse_ipv4_opt_2;
            8: parse_ipv4_opt_3;
            9: parse_ipv4_opt_4;
            default: parse_ipv4_opt_more;
        }
    }

    state parse_ipv4_opt_more {
        pkt.advance(160);
        transition select(hdr.ipv4.ihl) {
            10: parse_ipv4_opt_0;
            11: parse_ipv4_opt_1;
            12: parse_ipv4_opt_2;
            13: parse_ipv4_opt_3;
            14: parse_ipv4_opt_4;
            15: parse_ipv4_opt_5;
            default: reject;
        }
    }

    state parse_ipv4_opt_5 {
        pkt.advance(160);
        transition parse_ipv4_opt_0;
    }

    state parse_ipv4_opt_4 {
        pkt.advance(128);
        transition parse_ipv4_opt_0;
    }

    state parse_ipv4_opt_3 {
        pkt.advance(96);
        transition parse_ipv4_opt_0;
    }

    state parse_ipv4_opt_2 {
        pkt.advance(64);
        transition parse_ipv4_opt_0;
    }

    state parse_ipv4_opt_1 {
        pkt.advance(32);
        transition parse_ipv4_opt_0;
    }

    state parse_ipv4_opt_0 {
        transition select(hdr.ipv4.frag_offset, hdr.ipv4.protocol) {
            (0, IPPROTO_ICMP) : parse_icmp;
            (0, IPPROTO_ICMP6): parse_icmp;
            (0, IPPROTO_TCP)  : parse_tcp_ports;
            (0, IPPROTO_UDP)  : parse_udp;
            default           : consume_payload;
        }
    }

    state parse_ipv6 {
        pkt.extract(hdr.ipv6);
        transition select(hdr.ipv6.nexthdr) {
            IPPROTO_ICMP : parse_icmp;
            IPPROTO_ICMP6: parse_icmp;
            IPPROTO_TCP  : parse_tcp_ports;
            IPPROTO_UDP  : parse_udp;
            default      : consume_payload;
        }
    }

    state parse_icmp {
        pkt.extract(hdr.icmp);
        transition consume_payload;
    }

    state parse_udp {
        pkt.extract(hdr.ports);
        pkt.extract(hdr.udp);
        transition parse_application;
    }

    state parse_http_req {
        pkt.extract(hdr.http_req);
        transition consume_payload;
    }

    state parse_http_resp {
        pkt.extract(hdr.http_resp);
        transition consume_payload;
    }

    state parse_dns {
        pkt.extract(hdr.dns);
        transition consume_payload;
    }


    state parse_application {
        transition select(hdr.ports.sport, hdr.ports.dport) {
            (53, _): parse_dns;
            (_, 53): parse_dns;
            (80, _): parse_http_resp;
            (8080, _): parse_http_resp;
            (_, 80): parse_http_req;
            (_, 8080): parse_http_req;
            default: consume_payload;
        }
    }
    
    /* parse tcp ports and identify interesting application layer data via ports */
    state parse_tcp_ports {
        pkt.extract(hdr.ports);
        transition select(hdr.ports.sport, hdr.ports.dport) {
            (53, _): parse_tcp_and_dns;
            (_, 53): parse_tcp_and_dns;
            (80, _): parse_tcp_and_http_resp;
            (_, 80): parse_tcp_and_http_req;
            (8080, _): parse_tcp_and_http_resp;
            (_, 8080): parse_tcp_and_http_req;
            default: parse_tcp;
        }
    }

    // parse remaining tcp header fields, then consume rest (no tcp options or application layer data needed)
    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition consume_payload;
    }

    // parse remaining tcp header and options to access http request fields
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

    state parse_tcp_opt_more_http_req {
        pkt.advance(160);
        transition select(hdr.tcp.offset) {
            10: parse_tcp_no_options_http_req;
            11: skip_4_http_req;
            12: skip_8_http_req;
            13: skip_12_http_req;
            14: skip_16_http_req;
            15: skip_20_http_req;
            default: consume_payload;
        }
    }

    // no (more) options to parse
    state parse_tcp_no_options_http_req {
        transition parse_http_req;
    }

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

    // parse remaining tcp header and options to access http response fields
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

    // parse remaining tcp header and options to access dns fields */
    state parse_tcp_and_dns {
        pkt.extract(hdr.tcp);
        // TCP options are 0..10 words of 4 bytes, i.e., 0..40 bytes need to be skipped
        transition select(hdr.tcp.offset) {
            5: parse_tcp_no_options_dns;
            6: skip_4_dns;
            7: skip_8_dns;
            8: skip_12_dns;
            9: skip_16_dns;
            default: parse_tcp_opt_more_dns;
        }
    }

    state parse_tcp_opt_more_dns {
        pkt.advance(160);
        transition select(hdr.tcp.offset) {
            10: parse_tcp_no_options_dns;
            11: skip_4_dns;
            12: skip_8_dns;
            13: skip_12_dns;
            14: skip_16_dns;
            15: skip_20_dns;
            default: consume_payload;
        }
    }

    // no (more) options to parse
    state parse_tcp_no_options_dns {
        transition parse_dns;
    }

    state skip_4_dns {
        pkt.advance(32 * 1);
        transition parse_tcp_no_options_dns;
    }

    state skip_8_dns {
        pkt.advance(32 * 2);
        transition parse_tcp_no_options_dns;
    }

    state skip_12_dns {
        pkt.advance(32 * 3);
        transition parse_tcp_no_options_dns;
    }

    state skip_16_dns{
        pkt.advance(32 * 4);
        transition parse_tcp_no_options_dns;
    }

    state skip_20_dns {
        pkt.advance(32 * 5);
        transition parse_tcp_no_options_dns;
    }


    state consume_payload {
        pkt.extract(meta.data_start);
        // drop rest of packet beyond parsed headers as not of interest
        pkt.advance(32768); // 4 KB
        transition accept;
    }
}   

control Egress(inout egress_headers_t                            hdr,
               inout egress_meta_t                               meta,
               in    egress_intrinsic_metadata_t                 eg_intr_md,
               in    egress_intrinsic_metadata_from_parser_t     eg_prsr_md,
               inout egress_intrinsic_metadata_for_deparser_t    eg_dprsr_md,
               inout egress_intrinsic_metadata_for_output_port_t eg_oport_md)
{
    PRECISION_AGG_REG(PRECISION_WIDTH, bit<32>, 1, pkts, 0, register + 1)
    PRECISION_AGG_REG(PRECISION_WIDTH, bit<32>, 2, pkts, 0, register + 1)
    PRECISION_AGG_REG(PRECISION_WIDTH, bit<32>, 1, bytes, 0, register + (bit<32>)meta.total_len)
    PRECISION_AGG_REG(PRECISION_WIDTH, bit<32>, 2, bytes, 0, register + (bit<32>)meta.total_len)
    PRECISION_AGG_REG(PRECISION_WIDTH, bit<32>, 1, tcp_syn, 0, register + 1)
    PRECISION_AGG_REG(PRECISION_WIDTH, bit<32>, 2, tcp_syn, 0, register + 1)
    PRECISION_AGG_REG(PRECISION_WIDTH, bit<32>, 1, tcp_ack, 0, register + 1)
    PRECISION_AGG_REG(PRECISION_WIDTH, bit<32>, 2, tcp_ack, 0, register + 1)

    Register<bit<32>, bit<PRECISION_WIDTH>>(1 << PRECISION_WIDTH, 0) saved_1_start;
    RegisterAction<bit<32>, bit<PRECISION_WIDTH>, bit<32>>(saved_1_start) report_1_start = {
        void apply(inout bit<32> register, out bit<32> result) {
            if (hdr.mirror.info == HEADER_INFO_MIRROR_REPLACED) {
                register = hdr.ipfix.tstamp;
            }
            result = register;
        }
    };
    Register<bit<32>, bit<PRECISION_WIDTH>>(1 << PRECISION_WIDTH, 0) saved_2_start;
    RegisterAction<bit<32>, bit<PRECISION_WIDTH>, bit<32>>(saved_2_start) report_2_start = {
        void apply(inout bit<32> register, out bit<32> result) {
            if (hdr.mirror.info == HEADER_INFO_MIRROR_REPLACED) {
                register = hdr.ipfix.tstamp;
            }
            result = register;
        }
    };

    Register<bit<16>, bit<PRECISION_WIDTH>>(1 << PRECISION_WIDTH, 0) saved_1_flags;
    RegisterAction<bit<16>, bit<PRECISION_WIDTH>, bit<16>>(saved_1_flags) report_1_flags = {
        void apply(inout bit<16> register, out bit<16> result) {
            if (hdr.mirror.info == HEADER_INFO_MIRROR_REPLACED) {
                register = 4w0 ++ hdr.tcp.flags;
            } else {
                register = register | (4w0 ++ hdr.tcp.flags);
            }
            result = register;
        }
    };
    Register<bit<16>, bit<PRECISION_WIDTH>>(1 << PRECISION_WIDTH, 0) saved_2_flags;
    RegisterAction<bit<16>, bit<PRECISION_WIDTH>, bit<16>>(saved_2_flags) report_2_flags = {
        void apply(inout bit<16> register, out bit<16> result) {
            if (hdr.mirror.info == HEADER_INFO_MIRROR_REPLACED) {
                register = 4w0 ++ hdr.tcp.flags;
            } else {
                register = register | (4w0 ++ hdr.tcp.flags);
            }
            result = register;
        }
    };

    // header info retrieved from template packet and inserted into records
    REGISTERS(16, template_id, 1) = { APPLY(16) {
        if (hdr.template.template_id != 0) {
            register = hdr.template.template_id;
        }
        result = register;
    } };
    REGISTER(32, ipfix_seq) = { APPLY(32) {
        result = register;
        if (hdr.template.template_id == 0) {
            register = register + 1;
        }
    } };
    REGISTER(32, tstamp_base) = { APPLY(32) {
        if (hdr.ipfix.tstamp == 0) {
            result = (14w0 ++ eg_prsr_md.global_tstamp[47:30]) - register;
        } else {
            register = 14w0 ++ eg_prsr_md.global_tstamp[47:30];
            result = 32w0;
        }
    } };
    REGISTER(32, tstamp_offset) = { APPLY(32) {
        if (hdr.ipfix.tstamp != 0) {
            register = hdr.ipfix.tstamp;
        }
        result = register;
    } };

    // control plane determines addresses of collector (layers 2-4)
    action set_addresses_v4(bit<48> mac_saddr, bit<48> mac_daddr,
                            bit<32> ip_saddr, bit<32> ip_daddr,
                            bit<16> sport, bit<16> dport) {
        hdr.ethernet.setValid();
        hdr.ethernet.src_addr   = mac_saddr;
        hdr.ethernet.dst_addr   = mac_daddr;
        hdr.ethernet.ether_type = ETHERTYPE_IPV4;

        hdr.r_ipv4.setValid();
        hdr.r_ipv4.src_addr       = ip_saddr;
        hdr.r_ipv4.dst_addr       = ip_daddr;
        hdr.r_ipv4.protocol       = IPPROTO_UDP;
        hdr.r_ipv4.version        = 4;
        hdr.r_ipv4.ihl            = 5;
        hdr.r_ipv4.diffserv       = 0;
        hdr.r_ipv4.identification = 0;
        hdr.r_ipv4.flags          = 0;
        hdr.r_ipv4.frag_offset    = 0;
        hdr.r_ipv4.ttl            = 64;

        hdr.r_ports.setValid();
        hdr.r_ports.sport = sport;
        hdr.r_ports.dport = dport;

        hdr.r_udp.setValid();
    }

    action set_addresses_v6(bit<48> mac_saddr, bit<48> mac_daddr,
                            bit<128> ip_saddr, bit<128> ip_daddr,
                            bit<16> sport, bit<16> dport) {
        hdr.ethernet.setValid();
        hdr.ethernet.src_addr   = mac_saddr;
        hdr.ethernet.dst_addr   = mac_daddr;
        hdr.ethernet.ether_type = ETHERTYPE_IPV6;

        hdr.r_ipv6.setValid();
        hdr.r_ipv6.src_addr = ip_saddr;
        hdr.r_ipv6.dst_addr = ip_daddr;
        hdr.r_ipv6.nexthdr  = IPPROTO_UDP;
        hdr.r_ipv6.version  = 6;
        hdr.r_ipv6.tclass   = 0;
        hdr.r_ipv6.flow     = 0;
        hdr.r_ipv6.ttl      = 64;

        hdr.r_ports.setValid();
        hdr.r_ports.sport = sport;
        hdr.r_ports.dport = dport;

        hdr.r_udp.setValid();
    }

    table address_data {
        key = { eg_intr_md.egress_port : exact; }
        actions = { set_addresses_v4; set_addresses_v6; @defaultonly NoAction; }
        const default_action = NoAction();
        size = COLL_ADDR_SIZE;
    }

    action set_starttls(bit<8> value) {
        hdr.record.isStartTls = value;
    }

    table starttls_detect {
        key = { meta.data_start.data : exact; hdr.ports.dport : exact; }
        actions = { set_starttls; }
        const default_action = set_starttls(0);
        const entries = {
            (0x5354415254544c53, 25): set_starttls(1);
            (0x5354415254544c53, 110): set_starttls(1);
            (0x5354415254544c53, 143): set_starttls(1);
            (0x5354415254544c53, 587): set_starttls(1);
        }
    }

    apply {
        eg_dprsr_md.drop_ctl = 0;

        if (eg_intr_md.egress_port[6:0] == PKTGEN_INDEX) {
            // to recirculation port, ignore packet
            hdr.ctrl_pad.setValid();
        } else {
            // set headers for IPFIX, UDP, IPv4, Ethernet
            address_data.apply();
            hdr.ctrl_pad.setInvalid();

            if (hdr.mirror.isValid() && hdr.mirror.info == HEADER_INFO_MIRROR_DROP) {
                eg_dprsr_md.drop_ctl = 1;
            } else {
                hdr.ipfix.seq = ipfix_seq.execute(0);
                meta.tstamp_inc = tstamp_base.execute(0);
                hdr.ipfix.tstamp = tstamp_offset.execute(0) + meta.tstamp_inc;
            }

            if ((meta.ctrl.isValid() && meta.ctrl.template_index == TEMPLATE_INDEX_IPV4) || hdr.ipv4.isValid() || hdr.arp.isValid()) {
                hdr.record.template_id = template_id.execute(0);
                meta.total_len = hdr.ipv4.len;
            } else if ((meta.ctrl.isValid() && meta.ctrl.template_index == TEMPLATE_INDEX_IPV6) || hdr.ipv6.isValid()) {
                hdr.record.template_id = template_id.execute(1);
                meta.total_len = hdr.ipv6.len + hdr.ipv6.minSizeInBytes();
            } else {
                hdr.record.template_id = template_id.execute(0);
            }

            const int udp_len = hdr.r_ports.minSizeInBytes() + hdr.r_udp.minSizeInBytes();
            const int ipv4_udp_len = hdr.r_ipv4.minSizeInBytes() + udp_len;
            const int ipfix_len = hdr.ipfix.minSizeInBytes() + hdr.record.minSizeInBytes();

            if (meta.ctrl.isValid() && meta.ctrl.info == HEADER_INFO_TEMPLATE) {
                // template: only set lengths for all layers
                hdr.r_ipv4.len = (bit<16>)ipv4_udp_len + hdr.ipfix.len;
                hdr.r_ipv6.len = (bit<16>)udp_len + hdr.ipfix.len;
                hdr.r_udp.len  = (bit<16>)udp_len + hdr.ipfix.len;
                meta.csum_len  = (bit<16>)udp_len + hdr.ipfix.len;
            } else if (hdr.mirror.isValid()) {
                hdr.pad.setValid();

                if ((hdr.ports.isValid() || hdr.icmp.isValid()) && hdr.mirror.estimate[1:0] != 0) {

                    if (hdr.mirror.estimate[1:0] == 1) {

                        if (hdr.mirror.info == HEADER_INFO_MIRROR_DROP) {
                        
                            drop_1_pkts.execute(HASH(1));
                            drop_1_bytes.execute(HASH(1));
                        } else {
                            hdr.record.flowStartSeconds = report_1_start.execute(HASH(1));
                            hdr.record.packetDeltaCount = report_1_pkts.execute(HASH(1));
                            hdr.record.octetDeltaCount = report_1_bytes.execute(HASH(1));
                        }

                        if (hdr.mirror.info == HEADER_INFO_MIRROR_DROP && hdr.tcp.isValid()){
                            report_1_flags.execute(HASH(1));
                        } else {
                            hdr.record.tcpControlBits = report_1_flags.execute(HASH(1));
                        }

                        // tcp syn counter
                        if (hdr.mirror.info == HEADER_INFO_MIRROR_DROP) {
                            if (hdr.tcp.isValid() && hdr.tcp.flags & TCPFLAG_SYN == TCPFLAG_SYN) {
                                drop_1_tcp_syn.execute(HASH(1));
                            }
                        } else {
                            if (hdr.tcp.isValid() && hdr.tcp.flags & TCPFLAG_SYN == TCPFLAG_SYN) {
                                hdr.record.tcpSynTotalCount = report_1_tcp_syn.execute(HASH(1));
                            } else {
                                hdr.record.tcpSynTotalCount = report_without_update_1_tcp_syn.execute(HASH(1));
                            }
                        }

                        // tcp ack counter
                        if (hdr.mirror.info == HEADER_INFO_MIRROR_DROP) {
                            if (hdr.tcp.isValid() && hdr.tcp.flags & TCPFLAG_ACK == TCPFLAG_ACK) {
                                drop_1_tcp_ack.execute(HASH(1));
                            }
                        } else {
                            if (hdr.tcp.isValid() && hdr.tcp.flags & TCPFLAG_ACK == TCPFLAG_ACK) {
                                hdr.record.tcpAckTotalCount = report_1_tcp_ack.execute(HASH(1));
                            } else {
                                hdr.record.tcpAckTotalCount = report_without_update_1_tcp_ack.execute(HASH(1));
                            }
                        }

                    } else if (hdr.mirror.estimate[1:0] == 2) {
                        if (hdr.mirror.info == HEADER_INFO_MIRROR_DROP) {
                            drop_2_pkts.execute(HASH(2));
                            drop_2_bytes.execute(HASH(2));
                        } else{
                            hdr.record.flowStartSeconds = report_2_start.execute(HASH(2));
                            hdr.record.packetDeltaCount = report_2_pkts.execute(HASH(2));
                            hdr.record.octetDeltaCount = report_2_bytes.execute(HASH(2));
                        }

                        if (hdr.mirror.info == HEADER_INFO_MIRROR_DROP && hdr.tcp.isValid()){
                            report_2_flags.execute(HASH(2));
                        }else{
                            hdr.record.tcpControlBits = report_2_flags.execute(HASH(2));
                        }

                        // tcp syn counter
                        if (hdr.mirror.info == HEADER_INFO_MIRROR_DROP) {
                            if (hdr.tcp.isValid() && hdr.tcp.flags & TCPFLAG_SYN == TCPFLAG_SYN) {
                                drop_2_tcp_syn.execute(HASH(2));
                            }
                        } else {
                            if (hdr.tcp.isValid() && hdr.tcp.flags & TCPFLAG_SYN == TCPFLAG_SYN) {
                                hdr.record.tcpSynTotalCount = report_2_tcp_syn.execute(HASH(2));
                            } else {
                                hdr.record.tcpSynTotalCount = report_without_update_2_tcp_syn.execute(HASH(2));
                            }
                        }

                        // tcp ack counter
                        if (hdr.mirror.info == HEADER_INFO_MIRROR_DROP) {
                            if (hdr.tcp.isValid() && hdr.tcp.flags & TCPFLAG_ACK == TCPFLAG_ACK) {
                                drop_2_tcp_ack.execute(HASH(2));
                            }
                        } else {
                            if (hdr.tcp.isValid() && hdr.tcp.flags & TCPFLAG_ACK == TCPFLAG_ACK) {
                                hdr.record.tcpAckTotalCount = report_2_tcp_ack.execute(HASH(2));
                            } else {
                                hdr.record.tcpAckTotalCount = report_without_update_2_tcp_ack.execute(HASH(2));
                            }
                        }
                    }
                }

                if (hdr.mirror.info == HEADER_INFO_MIRROR_REPLACED || hdr.record.packetDeltaCount == 0) {
                    hdr.record.packetDeltaCount = 1;
                    hdr.record.octetDeltaCount = (bit<32>)meta.total_len;

                    if (hdr.tcp.isValid() && hdr.tcp.flags & TCPFLAG_SYN == TCPFLAG_SYN) {
                        hdr.record.tcpSynTotalCount = 1;
                    } else {
                        hdr.record.tcpSynTotalCount = 0;
                    }

                    if (hdr.tcp.isValid() && hdr.tcp.flags & TCPFLAG_ACK == TCPFLAG_ACK) {
                        hdr.record.tcpAckTotalCount = 1;
                    } else {
                        hdr.record.tcpAckTotalCount = 0;
                    }
                }

                if (hdr.record.flowStartSeconds == 0) {
                    // new entry with missing table setting
                    hdr.record.flowStartSeconds = hdr.ipfix.tstamp;
                    hdr.record.tcpControlBits[11:0] = hdr.tcp.flags;
                    hdr.record.tcpSequenceNumber = hdr.tcp.seq;
                    hdr.record.tcpWindowSize = hdr.tcp.window;

                    if (hdr.tcp.isValid() && hdr.tcp.flags & TCPFLAG_SYN == TCPFLAG_SYN) {
                        hdr.record.tcpSynTotalCount = 1;
                    } else {
                        hdr.record.tcpSynTotalCount = 0;
                    }

                    if (hdr.tcp.isValid() && hdr.tcp.flags & TCPFLAG_ACK == TCPFLAG_ACK) {
                        hdr.record.tcpAckTotalCount = 1;
                    } else {
                        hdr.record.tcpAckTotalCount = 0;
                    }
                }

                if (hdr.record.packetDeltaCount == 1) {
                    // only provide TTL for individual packets
                    if (hdr.ipv4.isValid()) {
                        hdr.record.ipTTL = hdr.ipv4.ttl;
                    } else if (hdr.ipv6.isValid()) {
                        hdr.record.ipTTL = hdr.ipv6.ttl;
                    }

                    // basic check to identify likely dns packets, https://stackoverflow.com/a/7566386
                    if (hdr.dns.isValid() && hdr.dns.qdcount == 1) {
                        meta.isDNS = 1;
                        hdr.record.isDNS = 1;
                        @in_hash {
                            hdr.record.DNSRequestType = (bit<8>) hdr.dns.query;
                            hdr.record.DNSResponseCode = (bit<8>) hdr.dns.rcode;
                        }
                    }

                    //report fragment offset
                    if (hdr.ipv4.isValid()) {
                        hdr.record.fragmentOffset = (bit<16>) hdr.ipv4.frag_offset;
                        hdr.record.fragmentIdentification = (bit<32>) hdr.ipv4.identification;
                        hdr.record.fragmentFlags = (bit<8>) hdr.ipv4.flags;
                    }
                    //ipv6 option parsing is currently not supported in our implementation, so we cannot report a fragment offset
                }

                // insert remaining extracted fields into packet
                hdr.record.ingressInterface = 7w0 ++ hdr.mirror.ingress_port;
                hdr.record.egressInterface  = 7w0 ++ hdr.mirror.egress_port;

                if (hdr.ipv4.isValid()) {
                    const int datav4_len = hdr.datav4.minSizeInBytes();
                    hdr.r_ipv4.len = ipv4_udp_len + ipfix_len + datav4_len;
                    hdr.r_ipv6.len = udp_len + ipfix_len + datav4_len;
                    hdr.r_udp.len = udp_len + ipfix_len + datav4_len;
                    hdr.ipfix.len = ipfix_len + datav4_len;
                    hdr.record.len = hdr.record.minSizeInBytes() + datav4_len;
                    meta.csum_len = udp_len + ipfix_len + datav4_len;

                    hdr.datav4.setValid();
                    hdr.datav4.sourceIPv4Address      = hdr.ipv4.src_addr;
                    hdr.datav4.destinationIPv4Address = hdr.ipv4.dst_addr;
                    hdr.record.protocolIdentifier     = hdr.ipv4.protocol;
                } else if (hdr.arp.isValid()){ // arp for ipv4 addresses
                    const int datav4_len = hdr.datav4.minSizeInBytes();
                    hdr.r_ipv4.len = ipv4_udp_len + ipfix_len + datav4_len;
                    hdr.r_ipv6.len = udp_len + ipfix_len + datav4_len;
                    hdr.r_udp.len = udp_len + ipfix_len + datav4_len;
                    hdr.ipfix.len = ipfix_len + datav4_len;
                    hdr.record.len = hdr.record.minSizeInBytes() + datav4_len;
                    meta.csum_len = udp_len + ipfix_len + datav4_len;

                    hdr.datav4.setValid();
                    hdr.datav4.sourceIPv4Address      = hdr.arp.src_ip;
                    hdr.datav4.destinationIPv4Address = hdr.arp.dst_ip;
                    hdr.record.protocolIdentifier = 222;
                } else {
                    const int datav4_len = hdr.datav4.minSizeInBytes();
                    hdr.r_ipv4.len = ipv4_udp_len + ipfix_len + datav4_len;
                    hdr.r_ipv6.len = udp_len + ipfix_len + datav4_len;
                    hdr.r_udp.len = udp_len + ipfix_len + datav4_len;
                    hdr.ipfix.len = ipfix_len + datav4_len;
                    hdr.record.len = hdr.record.minSizeInBytes() + datav4_len;
                    meta.csum_len = udp_len + ipfix_len + datav4_len;

                    hdr.datav4.setValid();
                    hdr.datav4.sourceIPv4Address      = 0;
                    hdr.datav4.destinationIPv4Address = 0;
                    hdr.record.protocolIdentifier     = 0;
                }

                if (hdr.ports.isValid()) {
                    hdr.record.sourceTransportPort      = hdr.ports.sport;
                    hdr.record.destinationTransportPort = hdr.ports.dport;
                } else if (hdr.icmp.isValid()) { 
                    /* provide ICMP type+code with destinationTransportPortas as done by YAF 
                    (cf. https://tools.netsa.cert.org/yaf/docs.html) */
                    hdr.record.sourceTransportPort      = 0;
                    hdr.record.destinationTransportPort = (bit<16>)(hdr.icmp.type ++ hdr.icmp.code); //0;
                    /*if (hdr.ipv4.isValid()) {
                        hdr.datav4.icmpTypeCodeIPv4 = (bit<16>)(hdr.icmp.type ++ hdr.icmp.code);
                    } else if (hdr.ipv6.isValid()) {
                        hdr.datav6.icmpTypeCodeIPv6 = (bit<16>)(hdr.icmp.type ++ hdr.icmp.code);
                    }*/
                } else {
                    hdr.record.sourceTransportPort      = 0;
                    hdr.record.destinationTransportPort = 0; 
                }
                
                if (hdr.http_req.isValid() && !(hdr.tcp.flags == 0x002 || hdr.tcp.flags == 0x012)) {
                    hdr.record.httpRequestMethod = hdr.http_req.httpRequestMethod;
                    //hdr.record.httpRequestTarget = hdr.http_req.httpRequestTarget;
                } else {
                    hdr.record.httpRequestMethod = 0;
                    //hdr.record.httpRequestTarget = 0;
                }
                
                if (hdr.http_resp.isValid() && !(hdr.tcp.flags == 0x002 || hdr.tcp.flags == 0x012)) {
                    hdr.record.httpStatusCode = hdr.http_resp.httpStatusCode;
                    hdr.record.httpMessageVersion = hdr.http_resp.httpMessageVersion;
                    //hdr.record.httpStatusMessage = hdr.http_resp.httpStatusMessage;
                } else {
                    hdr.record.httpStatusCode = 0;
                    hdr.record.httpMessageVersion = 0;
                    //hdr.record.httpStatusMessage = 0;
                }

                if (hdr.tcp.isValid()) {
                    starttls_detect.apply();
                }

                // remove the entire incoming packet
                hdr.vlan_tag.setInvalid();
                hdr.ipv4.setInvalid();
                hdr.ipv6.setInvalid();
                hdr.ports.setInvalid();
                hdr.tcp.setInvalid();
                hdr.udp.setInvalid();
                hdr.icmp.setInvalid();
                hdr.mirror.setInvalid();
                hdr.dns.setInvalid();
                hdr.http_req.setInvalid();
                hdr.http_resp.setInvalid();
                hdr.arp.setInvalid();
            }
        }
    }
}

control EgressDeparser(      packet_out                               pkt,
                       inout egress_headers_t                         hdr,
                       in    egress_meta_t                            meta,
                       in    egress_intrinsic_metadata_for_deparser_t eg_dprsr_md)
{
    Checksum() ipv4_checksum;
    Checksum() udp_template_checksum;
    Checksum() udp_record_checksum;

    apply {
        if (hdr.r_ipv4.isValid()) {
            hdr.r_ipv4.hdr_checksum = ipv4_checksum.update({
                hdr.r_ipv4.version,
                hdr.r_ipv4.ihl,
                hdr.r_ipv4.diffserv,
                hdr.r_ipv4.len,
                hdr.r_ipv4.identification,
                hdr.r_ipv4.flags,
                hdr.r_ipv4.frag_offset,
                hdr.r_ipv4.ttl,
                hdr.r_ipv4.protocol,
                hdr.r_ipv4.src_addr,
                hdr.r_ipv4.dst_addr
            });
        }
        if (hdr.record.isValid()) {
            hdr.r_udp.checksum = udp_record_checksum.update({
                hdr.r_ipv4.src_addr,
                hdr.r_ipv4.dst_addr,
                hdr.r_ipv6.src_addr,
                hdr.r_ipv6.dst_addr,
                meta.csum_len,
                8w0,
                hdr.r_ipv4.protocol,
                8w0,
                hdr.r_ipv6.nexthdr,
                hdr.r_ports.sport,
                hdr.r_ports.dport,
                hdr.r_udp.len,
                hdr.ipfix,
                hdr.record,
                hdr.datav4,
                hdr.datav6
            });
        }
        if (hdr.template.isValid()) {
            // includes partial checksum from control packet, over IPFIX template
            hdr.r_udp.checksum = udp_template_checksum.update({
                hdr.r_ipv4.src_addr,
                hdr.r_ipv4.dst_addr,
                hdr.r_ipv6.src_addr,
                hdr.r_ipv6.dst_addr,
                meta.csum_len,
                8w0,
                hdr.r_ipv4.protocol,
                8w0,
                hdr.r_ipv6.nexthdr,
                hdr.r_ports.sport,
                hdr.r_ports.dport,
                hdr.r_udp.len,
                hdr.ipfix,
                hdr.template,
                meta.ctrl.payload_checksum
            });
        }

        pkt.emit(hdr);
    }
}
