/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<2>  nextHopIndex_t;
typedef bit<1>  bitmapHit_t;
typedef bit<25> hashKey_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

struct metadata {
    nextHopIndex_t   next_hop_index;
    bitmapHit_t      bitmap_hit;
    hashKey_t        hash_key;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action set_next_hop_index(nextHopIndex_t nhi) {
        meta.next_hop_index = nhi;
    }

    action set_bitmap_hit(bitmapHit_t hit) {
        meta.bitmap_hit = hit;
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table next_hop_table {
        key = {  
            meta.next_hop_index: exact;
        }
        actions = {
            ipv4_forward;
            drop;
        }
        size = 4;
    }

    table lookup_table {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            set_next_hop_index;
        }
    }

    table hash_table {
        key = {
            meta.hash_key: exact;
        }
        actions = {
            set_next_hop_index;
        }
    }

    table bitmap_24 {
        key = {
            hdr.ipv4.dstAddr[31:8]: exact;
        }
        actions = {
            set_bitmap_hit;
        }
    }

    table bitmap_23 {
        key = {
            hdr.ipv4.dstAddr[31:9]: exact;
        }
        actions = {
            set_bitmap_hit;
        }
    }

    table bitmap_22 {
        key = {
            hdr.ipv4.dstAddr[31:10]: exact;
        }
        actions = {
            set_bitmap_hit;
        }
    }

    table bitmap_21 {
        key = {
            hdr.ipv4.dstAddr[31:11]: exact;
        }
        actions = {
            set_bitmap_hit;
        }
    }

    table bitmap_20 {
        key = {
            hdr.ipv4.dstAddr[31:12]: exact;
        }
        actions = {
            set_bitmap_hit;
        }
    }

    table bitmap_19 {
        key = {
            hdr.ipv4.dstAddr[31:13]: exact;
        }
        actions = {
            set_bitmap_hit;
        }
    }

    table bitmap_18 {
        key = {
            hdr.ipv4.dstAddr[31:14]: exact;
        }
        actions = {
            set_bitmap_hit;
        }
    }

    table bitmap_17 {
        key = {
            hdr.ipv4.dstAddr[31:15]: exact;
        }
        actions = {
            set_bitmap_hit;
        }
    }

    table bitmap_16 {
        key = {
            hdr.ipv4.dstAddr[31:16]: exact;
        }
        actions = {
            set_bitmap_hit;
        }
    }

    table bitmap_15 {
        key = {
            hdr.ipv4.dstAddr[31:17]: exact;
        }
        actions = {
            set_bitmap_hit;
        }
    }

    table bitmap_14 {
        key = {
            hdr.ipv4.dstAddr[31:18]: exact;
        }
        actions = {
            set_bitmap_hit;
        }
    }

    table bitmap_13 {
        key = {
            hdr.ipv4.dstAddr[31:19]: exact;
        }
        actions = {
            set_bitmap_hit;
        }
    }

    apply {
        if (!hdr.ipv4.isValid()) {
            return;
        }

        bool foundHop = false;
        bool skipToHash = false;

        if(lookup_table.apply().hit) {
            foundHop = true;
        }

        if(foundHop == false) {
            if(skipToHash == false) {    
                bitmap_24.apply();
                if(meta.bitmap_hit == 1){
                    skipToHash = true;
                    meta.hash_key = ((bit<25>)(hdr.ipv4.dstAddr[31:8] ++ (bit<1>)1)) << 0;
                }
            }

            if(skipToHash == false) {
                bitmap_23.apply();
                if(meta.bitmap_hit == 1){
                    skipToHash = true;
                    meta.hash_key = ((bit<25>)(hdr.ipv4.dstAddr[31:9] ++ (bit<1>)1)) << 1;
                }
            }

            if(skipToHash == false) {
                bitmap_22.apply();
                if(meta.bitmap_hit == 1){
                    skipToHash = true;
                    meta.hash_key = ((bit<25>)(hdr.ipv4.dstAddr[31:10] ++ (bit<1>)1)) << 2;
                }
            }

            if(skipToHash == false) {
                bitmap_21.apply();
                if(meta.bitmap_hit == 1){
                    skipToHash = true;
                    meta.hash_key = ((bit<25>)(hdr.ipv4.dstAddr[31:11] ++ (bit<1>)1)) << 3;
                }
            }

            if(skipToHash == false) {
                bitmap_20.apply();
                if(meta.bitmap_hit == 1){
                    skipToHash = true;
                    meta.hash_key = ((bit<25>)(hdr.ipv4.dstAddr[31:12] ++ (bit<1>)1)) << 4;
                }
            }

            if(skipToHash == false) {
                bitmap_19.apply();
                if(meta.bitmap_hit == 1){
                    skipToHash = true;
                    meta.hash_key = ((bit<25>)(hdr.ipv4.dstAddr[31:13] ++ (bit<1>)1)) << 5;
                }
            }

            if(skipToHash == false) {
                bitmap_18.apply();
                if(meta.bitmap_hit == 1){
                    skipToHash = true;
                    meta.hash_key = ((bit<25>)(hdr.ipv4.dstAddr[31:14] ++ (bit<1>)1)) << 6;
                }
            }

            if(skipToHash == false) {
                bitmap_17.apply();
                if(meta.bitmap_hit == 1){
                    skipToHash = true;
                    meta.hash_key = ((bit<25>)(hdr.ipv4.dstAddr[31:15] ++ (bit<1>)1)) << 7;
                }
            }

            if(skipToHash == false) {
                bitmap_16.apply();
                if(meta.bitmap_hit == 1){
                    skipToHash = true;
                    meta.hash_key = ((bit<25>)(hdr.ipv4.dstAddr[31:16] ++ (bit<1>)1)) << 8;
                }
            }

            if(skipToHash == false) {
                bitmap_15.apply();
                if(meta.bitmap_hit == 1){
                    skipToHash = true;
                    meta.hash_key = ((bit<25>)(hdr.ipv4.dstAddr[31:17] ++ (bit<1>)1)) << 9;
                }
            }

            if(skipToHash == false) {
                bitmap_14.apply();
                if(meta.bitmap_hit == 1){
                    skipToHash = true;
                    meta.hash_key = ((bit<25>)(hdr.ipv4.dstAddr[31:18] ++ (bit<1>)1)) << 10;
                }
            }

            if(skipToHash == false) {
                bitmap_13.apply();
                if(meta.bitmap_hit == 1){
                    skipToHash = true;
                    meta.hash_key = ((bit<25>)(hdr.ipv4.dstAddr[31:19] ++ (bit<1>)1)) << 11;
                }
            }

            if(!hash_table.apply().hit){
                return;
            }
        }

        next_hop_table.apply();
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
