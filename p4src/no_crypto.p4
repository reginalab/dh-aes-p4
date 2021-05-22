/*
    Copyright (C) 2021 Ramon Fontes, UFRN/Brazil
    Copyright (C) 2021 Emídio Neto, UFRN/Brazil
    Copyright (C) 2021 Fabricio Rodríguez, Unicamp/Brazil

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.
    
    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

// Standard headers
#include <core.p4>
#include <v1model.p4>


// useful for DH
typedef bit<256> keys_t;
typedef bit<48> macAddr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16> etherType;
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
    macAddr_t srcAddr;
    macAddr_t dstAddr;
}

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

#define ETHERTYPE_AES_TOY 0x9999

header aes_inout_t {
    bit<128> value;
}

struct my_headers_t {
    ethernet_t            ethernet;
    aes_inout_t           aes_inout;
}

header aes_meta_t {
    // internal state, 4 rows
}

header dh_meta_t {
    bit<256> secrect;
    bit<256> pu;
}
struct my_metadata_t {
    aes_meta_t aes;
}

parser MyParser(
    packet_in             packet,
    out   my_headers_t    hdr,
    inout my_metadata_t   meta,
    inout standard_metadata_t standard_metadata)
{
    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
           ETHERTYPE_AES_TOY    : parse_aes;
           default              : accept;
        }
    }

    state parse_aes {
        packet.extract(hdr.aes_inout);
        transition accept;
    }
}

control MyVerifyChecksum(inout my_headers_t hdr, inout my_metadata_t meta) {
    apply { }
}

control MyIngress(
    inout my_headers_t         hdr,
    inout my_metadata_t        meta,
    inout standard_metadata_t  standard_metadata)
{

    action l2_fwd() {
        hdr.aes_inout.setValid();
    }

    action set_egress_spec(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    table forward {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            set_egress_spec;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {

        if (forward.apply().hit) {

            if (hdr.ethernet.etherType == 0x9999) {
                l2_fwd();
            }
        }
    }
}

control MyEgress(
    inout my_headers_t        hdr,
    inout my_metadata_t       meta,
    inout standard_metadata_t standard_metadata) {

    apply {

    }
}

control MyComputeChecksum(
    inout my_headers_t  hdr,
    inout my_metadata_t meta)
{
    apply {   }
}

control MyDeparser(
    packet_out      packet,
    in my_headers_t hdr)
{

    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.aes_inout);
    }
}

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
