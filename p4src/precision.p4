/* Based on the descriptions of PRECISION by Ben Basat et al.:
    @article{basat2020precision,
        title={Designing Heavy-Hitter Detection Algorithms for Programmable Switches},
        author={Basat, Ran Ben and Chen, Xiaoqi and Einziger, Gil and Rottenstreich, Ori},
        journal={IEEE/ACM Transactions on Networking},  
        volume={28},
        number={3},
        year={2020},
        publisher={IEEE}
    }
*/

// vim: ts=4:sw=4:et:syntax=c

// basic register for storing flow identifying information
// actions: compare, overwrite
#define PRECISION_ID_REG(I, T, S, N, V, D)\
\
Register<T, bit<I>>(1 << I, D) precision_reg_ ## S ## _ ## N;\
RegisterAction<T, bit<I>, bit<1>>(precision_reg_ ## S ## _ ## N) precision_cmp_ ## S ## _ ## N = {\
    void apply(inout T register, out bit<1> result) {\
        result = (bit<1>)(register == V);\
    }\
};\
RegisterAction<T, bit<I>, void>(precision_reg_ ## S ## _ ## N) precision_upd_ ## S ## _ ## N = {\
    void apply(inout T register) {\
        register = V;\
    }\
};

// one stage of PRECISION: addresses, ports, icmp and a counter
// actions: increment counter (and return value), return value without change, set value (unused)
// _count contains 30 bits of flow-size estimate and 2 bits identifying stage number S
#define PRECISION_REGS(I, S)\
PRECISION_ID_REG(I, bit<32>, S, ports, hdr.ports.sport ++ hdr.ports.dport, 0)\
PRECISION_ID_REG(I, bit<16>, S, icmp, hdr.icmp.type ++ hdr.icmp.code, 0)\
PRECISION_ID_REG(I, ip_pair, S, ipv4, ({hdr.ipv4.src_addr, hdr.ipv4.dst_addr}), ({0, 0}))\
PRECISION_ID_REG(I, ip_pair, S, ipv6, ({meta.ipv6_src_low, meta.ipv6_dst_low}), ({0, 0}))\
PRECISION_ID_REG(I, bit<32>, S, ipv6_hash, meta.ipv6_hash, 0)\
Register<bit<32>, bit<I>>(1 << I, S) precision_reg_ ## S ## _count;\
RegisterAction<bit<32>, bit<I>, bit<32>>(precision_reg_ ## S ## _count) precision_est_ ## S ## _inc = {\
    void apply(inout bit<32> register, out bit<32> result) {\
        register = register + 4;\
        result = register;\
    }\
};\
RegisterAction<bit<32>, bit<I>, bit<32>>(precision_reg_ ## S ## _count) precision_est_ ## S ## _size = {\
    void apply(inout bit<32> register, out bit<32> result) {\
        result = register + 4;\
    }\
};\
RegisterAction<bit<32>, bit<I>, void>(precision_reg_ ## S ## _count) precision_est_ ## S ## _write = {\
    void apply(inout bit<32> register) {\
        register = hdr.mirror.min_flow;\
    }\
};\
RegisterAction<bit<32>, bit<I>, void>(precision_reg_ ## S ## _count) precision_est_ ## S ## _reset = {\
    void apply(inout bit<32> register) {\
        register = S;\
    }\
}

#define PRECISION_AGG_REG(I, T, S, N, V, U)\
\
Register<T, bit<I>>(1 << I, V) aggregate_ ## S ## _ ## N;\
RegisterAction<T, bit<I>, T>(aggregate_ ## S ## _ ## N) report_ ## S ## _ ## N = {\
    void apply(inout T register, out T result) {\
        result = U;\
        register = V;\
    }\
};\
RegisterAction<T, bit<I>, T>(aggregate_ ## S ## _ ## N) report_without_update_ ## S ## _ ## N = {\
    void apply(inout T register, out T result) {\
        result = register;\
        register = V;\
    }\
};\
RegisterAction<T, bit<I>, void>(aggregate_ ## S ## _ ## N) drop_ ## S ## _ ## N = {\
    void apply(inout T register) {\
        register = U;\
    }\
};
