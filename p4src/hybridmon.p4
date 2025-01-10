// vim: ts=4:sw=4:et:syntax=c

#include <core.p4>
#include <tna.p4>

#include "precision.p4"

#include "headers.p4"

#include "ingress.p4"

#include "egress.p4"

Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;
