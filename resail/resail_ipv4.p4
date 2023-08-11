/*
Copyright 2021 Intel Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <core.p4>
// The following line is not needed when using Intel Tofino P4
// compiler.  It is only here to be able to use open source p4test
// with tna.p4 include file in Open-Tofino repository for syntax
// checking.
#define __TARGET_TOFINO__ 1
#include <tna.p4>

#include <stdheaders.p4>

header bridge_metadata_t {
    // user-defined metadata carried over from ingress to egress.
}

struct ingress_headers_t {
    bridge_metadata_t bridge_md;
    ethernet_h ethernet;
    ipv4_h ipv4;
}

struct egress_headers_t {
    bridge_metadata_t bridge_md;
    ethernet_h ethernet;
    ipv4_h ipv4;
}

struct ingress_metadata_t {
    // user-defined ingress metadata
}

struct egress_metadata_t {
    // user-defined egress metadata
}

parser IngressParser(
    packet_in pkt,
    out ingress_headers_t  ig_hdr,
    out ingress_metadata_t ig_md,
    out ingress_intrinsic_metadata_t ig_intr_md)
{
    state start {
        // parser code begins here
        transition parse_ethernet;
    }
    state parse_ethernet {
        pkt.extract(ig_hdr.ethernet);
        transition parse_ipv4;
    }
    state parse_ipv4 {
        pkt.extract(ig_hdr.ipv4);
        transition accept;
    }
}

control Ingress(
    inout ingress_headers_t  ig_hdr,
    inout ingress_metadata_t ig_md,
    in    ingress_intrinsic_metadata_t              ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t  ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t       ig_tm_md)
{
    apply {
        // ingress control code here
    }
}

control IngressDeparser(
    packet_out pkt,
    inout ingress_headers_t  ig_hdr,
    in    ingress_metadata_t ig_md,
    in    ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md)
{
    apply {
        // emit headers for out-of-ingress packets here
    }
}

parser EgressParser(
    packet_in pkt,
    out egress_headers_t  eg_hdr,
    out egress_metadata_t eg_md,
    out egress_intrinsic_metadata_t eg_intr_md)
{
    state start {
        // parser code begins here
        transition accept;
    }
}

control Egress(
    inout egress_headers_t  eg_hdr,
    inout egress_metadata_t eg_md,
    in    egress_intrinsic_metadata_t                 eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t     eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t    eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t eg_oport_md)
{
    apply {
        // egress control code here
    }
}

control EgressDeparser(
    packet_out pkt,
    inout egress_headers_t  eg_hdr,
    in    egress_metadata_t eg_md,
    in    egress_intrinsic_metadata_for_deparser_t eg_dprsr_md)
{
    apply {
        // emit desired egress headers here
    }
}

Pipeline(IngressParser(),
         Ingress(),
         IngressDeparser(),
         EgressParser(),
         Egress(),
         EgressDeparser()) pipe;

// In a multi-pipe Tofino device, the TNA package instantiation below
// implies that the same P4 code behavior is loaded into all of the
// pipes.

Switch(pipe) main;