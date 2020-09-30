/*
  Ido Barnea
  Cisco Systems, Inc.
*/

/*
  Copyright (c) 2016-2017 Cisco Systems, Inc.

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

#include <netinet/in.h>
#include "common/basic_utils.h"
#include "common/Network/Packet/EthernetHeader.h"
#include "common/Network/Packet/IPHeader.h"
#include "common/Network/Packet/IPv6Header.h"
#include "common/Network/Packet/TcpHeader.h"
#include "common/Network/Packet/VLANHeader.h"
#include "common/Network/Packet/MPLSHeader.h"
#include "common/Network/Packet/GREHeader.h"
#include "pkt_gen.h"
#include "flow_stat_parser.h"
#include "bp_sim.h"

CFlowStatParser::CFlowStatParser(CFlowStatParser_mode mode) {
    reset();
    switch(mode) {
    case FLOW_STAT_PARSER_MODE_HW:
        m_flags = FSTAT_PARSER_VLAN_SUPP;
        break;
    case FLOW_STAT_PARSER_MODE_SW:
        m_flags = FSTAT_PARSER_VLAN_SUPP | FSTAT_PARSER_QINQ_SUPP | FSTAT_PARSER_MPLS_SUPP;
        m_mpls_def_ethertype = 0;
        break;
    // In 82599 we configure the card to either always use VLAN, or never use
    case FLOW_STAT_PARSER_MODE_82599:
        m_flags = 0;
        break;
    case FLOW_STAT_PARSER_MODE_82599_vlan:
        m_flags = FSTAT_PARSER_VLAN_SUPP | FSTAT_PARSER_VLAN_NEEDED;
        break;
    }
}

void CFlowStatParser::init(uint16_t port_id) {
    reset();
    if (CGlobalInfo::m_options.m_ip_cfg[port_id].get_vxlan_fs()) {
        set_tunnel_skip(CFlowStatParser::FLOW_STAT_PARSER_TUNNEL_VXLAN);
        set_tunnel_ethtype(0);
        set_tunnel_uport(4789);
    }
    else if (CGlobalInfo::m_options.m_ip_cfg[port_id].get_gre_tun()) {
        set_tunnel_skip(CFlowStatParser::FLOW_STAT_PARSER_TUNNEL_GRE);
    }
    else if (CGlobalInfo::m_options.m_ip_cfg[port_id].get_udp_tun()) {
        set_tunnel_skip(CFlowStatParser::FLOW_STAT_PARSER_TUNNEL_UDP);
        set_tunnel_ethtype(CGlobalInfo::m_options.m_ip_cfg[port_id].get_udp_ethtype());
        set_tunnel_uport(CGlobalInfo::m_options.m_ip_cfg[port_id].get_udp_tun());
    }
    m_mpls_def_ethertype = CGlobalInfo::m_options.m_ip_cfg[port_id].get_mpls_default();
    auto mpls_ethtype = CGlobalInfo::m_options.m_ip_cfg[port_id].get_mpls_ethtype();
    if (!mpls_ethtype.empty()) {
        m_mpls_ethertype = mpls_ethtype;
    }
}

void CFlowStatParser::reset() {
    m_start = 0;
    m_len = 0;
    m_ipv4 = 0;
    m_ipv6 = 0;
    m_l4_proto = 0;
    m_l4 = 0;
    m_next_header = 0;
}

std::string CFlowStatParser::get_error_str(CFlowStatParser_err_t err) {
    std::string base = "Failed parsing given packet for flow stat. ";

    switch(err) {
    case FSTAT_PARSER_E_OK:
        return "";
    case FSTAT_PARSER_E_TOO_SHORT:
        return base + " Packet too short";
    case FSTAT_PARSER_E_SHORT_IP_HDR:
        return base + " Packet IP header too short";
    case FSTAT_PARSER_E_VLAN_NOT_SUP:
        return base + " NIC does not support vlan (for 82599, you can try starting TRex with --vlan)";
    case FSTAT_PARSER_E_QINQ_NOT_SUP:
        return base + " NIC does not support Q in Q";
    case FSTAT_PARSER_E_MPLS_NOT_SUP:
        return base + " NIC does not support MPLS";
    case FSTAT_PARSER_E_UNKNOWN_HDR:
        return base + " NIC does not support given L2 header type";
    case FSTAT_PARSER_E_VLAN_NEEDED:
        return base + " NIC does not support packets with no vlan "
                      "(If you used --vlan command line arg, try to remove it)";
    }

    return "";
}

CFlowStatParser_err_t CFlowStatParser::parse(uint8_t *p, uint16_t len) {
    CFlowStatParser_err_t res = _parse(p, len);
    if(res != FSTAT_PARSER_E_OK)
        return res;

    if (get_tunnel_skip()) {
        // printf("Skiping Tunnel\n");
        uint16_t tunnel_payload = get_tunnel_rx_payload_offset(p, len);
        if (tunnel_payload) {
            // printf("Reparsing\n");
            res = _parse(p + tunnel_payload, len - tunnel_payload, m_next_header);
            // printf("Reparsing result = '%d'\n", res);
        }
    }

    return (res);
}

CFlowStatParser_err_t CFlowStatParser::_parse(uint8_t * p, uint16_t len, uint16_t next_hdr) {
    int min_len = 0;
    bool finished = false;
    bool has_vlan = false;
    reset();

    m_start = p;
    m_len = len;

    while (! finished) {
        // printf("Next header is = '%d'\n", next_hdr);
        switch( next_hdr ) {
        case 0: {
            // printf("Parsing eth\n");
            min_len += ETH_HDR_LEN;
            if (len < min_len)
                return FSTAT_PARSER_E_TOO_SHORT;

            EthernetHeader *ether = (EthernetHeader *)p;
            next_hdr = ether->getNextProtocol();

            p += ETH_HDR_LEN;
        } break;

        case EthernetHeader::Protocol::IP : {
            // printf("Parsing ipv4\n");
            min_len += IPV4_HDR_LEN;
            if (len < min_len)
                return FSTAT_PARSER_E_SHORT_IP_HDR;

            m_ipv4 = (IPHeader *) p;
            m_l4 = ((uint8_t *)m_ipv4) + m_ipv4->getHeaderLength();
            m_l4_proto = m_ipv4->getProtocol();
            finished = true;
        } break;

        case EthernetHeader::Protocol::IPv6 :
            // printf("Parsing ipv6\n");
            min_len += IPV6_HDR_LEN;
            if (len < min_len)
                return FSTAT_PARSER_E_SHORT_IP_HDR;
            m_ipv6 = (IPv6Header *) p;
            finished = true;
            break;

        case EthernetHeader::Protocol::QINQ :
            if (! (m_flags & FSTAT_PARSER_QINQ_SUPP))
                return FSTAT_PARSER_E_QINQ_NOT_SUP;
        case EthernetHeader::Protocol::VLAN : {
            // printf("Parsing vlan\n");
            if (! (m_flags & FSTAT_PARSER_VLAN_SUPP))
                return FSTAT_PARSER_E_VLAN_NOT_SUP;
            // In QINQ, we also allow multiple 0x8100 headers
            if (has_vlan && (! (m_flags & FSTAT_PARSER_QINQ_SUPP)))
                return FSTAT_PARSER_E_QINQ_NOT_SUP;
            has_vlan = true;
            min_len += sizeof(VLANHeader);
            if (len < min_len)
                return FSTAT_PARSER_E_TOO_SHORT;
            VLANHeader *vlan = (VLANHeader *)p;
            p += sizeof(VLANHeader);
            next_hdr = vlan->getNextProtocolHostOrder();
        } break;

        case EthernetHeader::Protocol::MPLS_Unicast :
        case EthernetHeader::Protocol::MPLS_Multicast : {
            // printf("Parsing mpls\n");
            if (! (m_flags & FSTAT_PARSER_MPLS_SUPP))
                return FSTAT_PARSER_E_MPLS_NOT_SUP;

            min_len += MPLS_HDR_LEN;
            if(len < min_len)
                return FSTAT_PARSER_E_TOO_SHORT;

            MPLSHeader* mpls = (MPLSHeader *) p;
            // printf("MPLS Data = '%08x'(lable=%d, bos=%d)\n", PKT_NTOHL(mpls->data), mpls->getLabel(), mpls->getBottomOfStack());
            if (mpls->getBottomOfStack()) {
                uint32_t ethtype = get_mpls_ethertype(mpls->getLabel());
                if (ethtype < 0)
                    return FSTAT_PARSER_E_UNKNOWN_HDR;

                next_hdr = ethtype;
            } else {
                next_hdr = EthernetHeader::Protocol::MPLS_Unicast;
            }

            p += MPLS_HDR_LEN;
        } break;

        default:
            // printf("Unknown header\n");
            return FSTAT_PARSER_E_UNKNOWN_HDR;
        }
    }

    if (unlikely(m_flags & FSTAT_PARSER_VLAN_NEEDED) && ! has_vlan) {
        return FSTAT_PARSER_E_VLAN_NEEDED;
    }
    return FSTAT_PARSER_E_OK;
}

#define VXLAN_LEN 8

uint16_t CFlowStatParser::get_tunnel_rx_payload_offset(uint8_t *pkt, uint16_t len) {
    uint16_t payload_len;
    if ( get_payload_len(pkt, len, payload_len) < 0 ) {
        return 0;
    }

    switch(m_tunnel_type) {
        case FLOW_STAT_PARSER_TUNNEL_VXLAN:
            if (payload_len < VXLAN_LEN) {
                return 0;
            }
            payload_len -= VXLAN_LEN;
        case FLOW_STAT_PARSER_TUNNEL_UDP:
            if ( m_l4_proto != IPPROTO_UDP ) {
                return 0;
            }
            if ( m_l4_port != m_udp_tun_port ) {
                // printf("UDP port(%d) is not for tunnel UDP port (%d)\n", m_l4_port, m_udp_tun_port);
                return 0;
            }

            m_next_header = m_tunnel_ethtype;
            break;
        case FLOW_STAT_PARSER_TUNNEL_GRE:
            if ( m_l4_proto != IPPROTO_GRE ) {
                return 0;
            }
            if (payload_len < GRE_HDR_LEN) {
                return 0;
            }
            payload_len -= GRE_HDR_LEN;
            break;
        default:
            return 0;
    }

    // printf("len(%d) - payload_len(%d) = %d\n", len, payload_len, (len - payload_len));
    return (len - payload_len);
}

// arg is uint32_t in below two functions because we want same function to work for IPv4 and IPv6
int CFlowStatParser::get_ip_id(uint32_t &ip_id) {
    if (m_ipv4) {
        ip_id = m_ipv4->getId();
        return 0;
    }

    if (m_ipv6) {
        ip_id = m_ipv6->getFlowLabel();
        return 0;
    }

    return -1;
}

void CFlowStatParser::set_ip_id(uint32_t new_id) {
    if (m_ipv4) {
        uint16_t ipv4_ip_id = (uint16_t) new_id;
        // Updating checksum, not recalculating, so if someone put bad checksum on purpose, it will stay bad
        m_ipv4->updateCheckSum(PKT_NTOHS(m_ipv4->getId()), PKT_NTOHS(ipv4_ip_id));
        m_ipv4->setId(ipv4_ip_id);
    }

    if (m_ipv6) {
        m_ipv6->setFlowLabel(new_id);
    }
}

// In Mellanox and VIC cards, we use TOS to mark packets to go to CPU
void CFlowStatParser::set_tos_to_cpu() {
    if (m_ipv4) {
        // Updating checksum, not recalculating, so if someone put bad checksum on purpose, it will stay bad
        m_ipv4->updateCheckSum(PKT_NTOHS(m_ipv4->getFirstWord()), PKT_NTOHS(m_ipv4->getFirstWord()
                                                                            | TOS_GO_TO_CPU));
        m_ipv4->setTOS(m_ipv4->getTOS() | TOS_GO_TO_CPU);
    }

    if (m_ipv6) {
        m_ipv6->setTrafficClass(m_ipv6->getTrafficClass() | TOS_GO_TO_CPU);
    }
}


int CFlowStatParser::get_l3_proto(uint16_t &proto) {
    if (m_ipv4) {
        proto = EthernetHeader::Protocol::IP;
        return 0;
    }

    if (m_ipv6) {
        proto = EthernetHeader::Protocol::IPv6;
        return 0;
    }

    return -1;
}

int CFlowStatParser::get_l4_proto(uint8_t &proto) {
    if (m_ipv4) {
        proto = m_ipv4->getProtocol();
        return 0;
    }

    if (m_ipv6) {
        if (!m_l4) {
            uint16_t payload_len;
            // in IPv6 we calculate l4 proto only when running get_payload_len
            get_payload_len(m_start, m_len, payload_len);
        }
        proto = m_l4_proto;
        return 0;
    }

    return -1;
}

uint16_t CFlowStatParser::get_pkt_size() {
    uint16_t ip_len=0;

    if (m_ipv4) {
        ip_len = m_ipv4->getTotalLength();
    } else if (m_ipv6) {
        ip_len = m_ipv6->getHeaderLength() + m_ipv6->getPayloadLen();
    }
    return ( ip_len + m_vlan_offset + ETH_HDR_LEN);
}

uint8_t CFlowStatParser::get_protocol(){
    uint8_t proto = 0;
    if (m_ipv4) {
        proto = m_ipv4->getProtocol();
    }
    if (m_ipv6) {
        proto = m_ipv6->getNextHdr();
    }
    return (proto);
}

bool CFlowStatParser::is_fs_latency(){
    uint8_t tos = 0;
    if (m_ipv4) {
        tos = m_ipv4->getTOS();
    }
    if (m_ipv6) {
        tos = m_ipv6->getTrafficClass();
    }
    return ((tos&0x01)==0x01)?true:false;
}

uint8_t CFlowStatParser::get_ttl(){
    if (m_ipv4) {
        return ( m_ipv4->getTimeToLive() );
    }
    if (m_ipv6) {
        return ( m_ipv6->getHopLimit() );
    }
    return (0);
}

// calculate the payload len. Do not want to do this in parse(), since this is required only in
// specific cases, while parse is used in many places (including on packet RX path, where we want to be as fast as possible)
int CFlowStatParser::get_payload_len(uint8_t *p, uint16_t len, uint16_t &payload_len) {
    uint16_t l2_header_len = 0;
    uint16_t l4_header_len = 0;
    uint8_t *p_l3 = NULL;
    uint8_t *p_l4 = NULL;
    if (!m_ipv4 && !m_ipv6) {
        payload_len = len - ETH_HDR_LEN;
        return 0;
    }

    if (m_ipv4) {
        l2_header_len = ((uint8_t *)m_ipv4) - p;
        m_l4_proto = m_ipv4->getProtocol();
        m_l4_port = 0;
        p_l3 = (uint8_t *)m_ipv4;
        p_l4 = p_l3 + m_ipv4->getHeaderLength();
    } else if (m_ipv6) {
        l2_header_len = ((uint8_t *)m_ipv6) - p;
        m_l4_proto = m_ipv6->getl4Proto((uint8_t *)m_ipv6, len - l2_header_len, p_l4);
        m_l4_port = 0;
    }

    switch (m_l4_proto) {

    case IPPROTO_UDP: {
        // printf("Parsing UDP header\n");
        if ((p_l4 + UDP_HEADER_LEN) > (p + len)) {
            //Not enough space for UDP header
            // printf("Not enough space for UDP Header\n");
            payload_len = 0;
            return -2;
        }
        UDPHeader* p_udp = (UDPHeader*)p_l4;
        m_l4_port = p_udp->getDestPort();
        l4_header_len = 8;
    } break;

    case IPPROTO_TCP: {
        if ((p_l4 + TCP_HEADER_LEN) > (p + len)) {
            //Not enough space for TCP header
            payload_len = 0;
            return -2;
        }
        TCPHeader *p_tcp = (TCPHeader *)p_l4;
        l4_header_len = p_tcp->getHeaderLength();
        m_l4_port = p_tcp->getDestPort();
    } break;

    case IPPROTO_ICMP: {
        l4_header_len = 8;
    } break;

    case IPPROTO_GRE: {
        //l4_header_len = GRE_HDR_LEN;
        GREHeader* gre = (GREHeader*)p_l4;
        m_next_header = gre->getProto();
    }break;

    default: {
        l4_header_len = 0;
    } break;

    }

    payload_len = len - (p_l4 - p) - l4_header_len;
    // printf("Payload length = '%d'\n", payload_len);

    if (payload_len <= 0) {
        payload_len = 0;
        return -3;
    }

    return 0;
}

static const uint16_t TEST_IP_ID = 0xabcd;
static const uint16_t TEST_IP_ID2 = 0xabcd;

int CFlowStatParserTest::verify_pkt_one_parser(uint8_t * p, uint16_t pkt_size, uint16_t payload_len, uint32_t ip_id
                                               , uint8_t l4_proto, CFlowStatParser &parser, CFlowStatParser_err_t exp_ret) {
    CFlowStatParser_err_t ret;
    uint32_t pkt_ip_id = 0;
    uint8_t pkt_l4_proto;
    uint16_t pkt_payload_len;

    ret = parser.parse(p, pkt_size);
    assert(ret == exp_ret);

    if (ret == FSTAT_PARSER_E_OK) {
        parser.get_ip_id(pkt_ip_id);
        assert(pkt_ip_id == ip_id);
        parser.set_ip_id(TEST_IP_ID2);
        // utl_DumpBuffer(stdout, test_pkt, sizeof(test_pkt), 0);
        parser.get_ip_id(ip_id);
        assert(ip_id == TEST_IP_ID2);
        if (parser.m_ipv4)
            assert(parser.m_ipv4->isChecksumOK() == true);
        assert(parser.get_l4_proto(pkt_l4_proto) == 0);
        assert(pkt_l4_proto == l4_proto);
        uint32_t ret2 = parser.get_payload_len(p, pkt_size, pkt_payload_len);
        assert(ret2 == 0);
        assert(pkt_payload_len == payload_len);
    }

    return 0;
}

int CFlowStatParserTest::verify_pkt(uint8_t *p, uint16_t pkt_size, uint16_t payload_len, uint32_t ip_id, uint8_t l4_proto
                                    , CFlowStatParserTest_exp_err_t exp_err) {
    int ret;
    int ret_val = 0;
    CFlowStatParser parser_hw(CFlowStatParser::FLOW_STAT_PARSER_MODE_HW);
    CFlowStatParser parser_sw(CFlowStatParser::FLOW_STAT_PARSER_MODE_SW);
    CFlowStatParser parser82599(CFlowStatParser::FLOW_STAT_PARSER_MODE_82599);
    CFlowStatParser parser82599_vlan(CFlowStatParser::FLOW_STAT_PARSER_MODE_82599_vlan);

    printf ("  ");
    // printf("Hardware mode parser");
    ret = verify_pkt_one_parser(p, pkt_size, payload_len, ip_id, l4_proto, parser_hw, exp_err.m_hw);
    ret_val = ret;
    if (ret != 0)
        ret_val = -1;

    // printf(", software mode parser");
    ret = verify_pkt_one_parser(p, pkt_size, payload_len, ip_id, l4_proto, parser_sw, exp_err.m_sw);
    ret_val = ret;
    if (ret != 0)
        ret_val = -1;

    // printf(", 82599 parser");
    ret = verify_pkt_one_parser(p, pkt_size, payload_len, ip_id, l4_proto, parser82599, exp_err.m_82599);
    ret_val |= ret;
    if (ret != 0)
        ret_val = -1;

    // printf(", 82599 vlan parser");
    ret = verify_pkt_one_parser(p, pkt_size, payload_len, ip_id, l4_proto, parser82599_vlan, exp_err.m_82599_vlan);
    ret_val |= ret;
    if (ret != 0)
        ret_val = -1;

    // printf("\n");

    return 0;
}

int CFlowStatParserTest::test_one_pkt(const char *name, uint16_t ether_type, uint8_t l4_proto, int vlan_num
                                      , CFlowStatParserTest_exp_err_t exp_err) {
    CTestPktGen gen;
    uint8_t *p;
    int pkt_size;
    uint16_t payload_len = 18;
    uint16_t pkt_flags;
    int ret = 0;

    // printf("%s - ", name);

    // in case of IPv6, we add rx_check header, just to make sure we know how to parse with multiple headers
    switch (vlan_num) {
    case 1:
        pkt_flags = DPF_VLAN | DPF_RXCHECK;
        break;
    case 0:
        pkt_flags = DPF_RXCHECK;
        break;
    case 2:
        pkt_flags = DPF_QINQ | DPF_RXCHECK;
        break;
    default:
        // printf("Internal error: vlan_num = %d\n", vlan_num);
        exit(-1);
    }

    p = (uint8_t *)gen.create_test_pkt(ether_type, l4_proto, 255, TEST_IP_ID, pkt_flags, payload_len, pkt_size);
    ret = verify_pkt(p, pkt_size, payload_len, TEST_IP_ID, l4_proto, exp_err);
    free(p);

    return ret;
}

int CFlowStatParserTest::test() {
    uint8_t tcp = IPPROTO_TCP, udp = IPPROTO_UDP, icmp = IPPROTO_ICMP;
    uint16_t ipv4 = EthernetHeader::Protocol::IP, ipv6 = EthernetHeader::Protocol::IPv6;
    CFlowStatParserTest_exp_err_t exp_ret;

    // no vlan tests
    exp_ret.m_hw = FSTAT_PARSER_E_OK;
    exp_ret.m_sw = FSTAT_PARSER_E_OK;
    exp_ret.m_82599 = FSTAT_PARSER_E_OK;
    exp_ret.m_82599_vlan = FSTAT_PARSER_E_VLAN_NEEDED;
    test_one_pkt("IPv4 TCP", ipv4, tcp, 0, exp_ret);
    test_one_pkt("IPv4 UDP", ipv4, udp, 0, exp_ret);
    test_one_pkt("IPv4 ICMP", ipv4, icmp, 0, exp_ret);
    test_one_pkt("IPv6 TCP", ipv6, tcp, 0, exp_ret);
    test_one_pkt("IPv6 UDP", ipv6, udp, 0, exp_ret);
    test_one_pkt("IPv4 IGMP", ipv4, IPPROTO_IGMP, 0, exp_ret);

    // vlan tests
    exp_ret.m_hw = FSTAT_PARSER_E_OK;
    exp_ret.m_sw = FSTAT_PARSER_E_OK;
    exp_ret.m_82599 = FSTAT_PARSER_E_VLAN_NOT_SUP;
    exp_ret.m_82599_vlan = FSTAT_PARSER_E_OK;;
    test_one_pkt("IPv4 TCP VLAN", ipv4, tcp, 1, exp_ret);
    test_one_pkt("IPv4 UDP VLAN", ipv4, udp, 1, exp_ret);
    test_one_pkt("IPv4 ICMP VLAN", ipv4, icmp, 1, exp_ret);
    test_one_pkt("IPv6 TCP VLAN", ipv6, tcp, 1, exp_ret);
    test_one_pkt("IPv6 UDP VLAN", ipv6, udp, 1, exp_ret);

    // qinq tests
    exp_ret.m_hw = FSTAT_PARSER_E_QINQ_NOT_SUP;
    exp_ret.m_sw = FSTAT_PARSER_E_OK;
    exp_ret.m_82599 = FSTAT_PARSER_E_QINQ_NOT_SUP;
    exp_ret.m_82599_vlan = FSTAT_PARSER_E_QINQ_NOT_SUP;
    test_one_pkt("IPv4 TCP QINQ", ipv4, tcp, 2, exp_ret);
    test_one_pkt("IPv4 UDP QINQ", ipv4, udp, 2, exp_ret);
    test_one_pkt("IPv4 ICMP QINQ", ipv4, icmp, 2, exp_ret);
    test_one_pkt("IPv6 TCP QINQ", ipv6, tcp, 2, exp_ret);
    test_one_pkt("IPv6 UDP QINQ", ipv6, udp, 2, exp_ret);

    // bad packets tests
    exp_ret.m_hw = FSTAT_PARSER_E_UNKNOWN_HDR;
    exp_ret.m_sw = FSTAT_PARSER_E_UNKNOWN_HDR;
    exp_ret.m_82599 = FSTAT_PARSER_E_UNKNOWN_HDR;
    exp_ret.m_82599_vlan = FSTAT_PARSER_E_UNKNOWN_HDR;
    test_one_pkt("BAD l3 type", 0xaa, icmp, 0, exp_ret);

    exp_ret.m_82599 = FSTAT_PARSER_E_VLAN_NOT_SUP;
    test_one_pkt("VLAN + BAD l3 type", 0xaa, icmp, 1, exp_ret);

    return 0;
}

CFlowStatParser_err_t CPassAllParser::parse(uint8_t *pkt, uint16_t len) {
    reset();

    if (len < ETH_HDR_LEN)
        return FSTAT_PARSER_E_TOO_SHORT;

    m_len = len;

    return FSTAT_PARSER_E_OK;
}

bool CSimplePacketParser::Parse(){

    rte_mbuf_t * m=m_m;
    uint8_t *p=rte_pktmbuf_mtod(m, uint8_t*);
    EthernetHeader *m_ether = (EthernetHeader *)p;
    IPHeader * ipv4=0;
    IPv6Header * ipv6=0;
    m_vlan_offset=0;
    uint8_t protocol = 0;

    // Retrieve the protocol type from the packet
    switch( m_ether->getNextProtocol() ) {
    case EthernetHeader::Protocol::IP :
        // IPv4 packet
        ipv4=(IPHeader *)(p+14);
        m_l4 = (uint8_t *)ipv4 + ipv4->getHeaderLength();
        protocol = ipv4->getProtocol();
        break;
    case EthernetHeader::Protocol::IPv6 :
        // IPv6 packet
        ipv6=(IPv6Header *)(p+14);
        m_l4 = (uint8_t *)ipv6 + ipv6->getHeaderLength();
        protocol = ipv6->getNextHdr();
        break;
    case EthernetHeader::Protocol::VLAN :
        m_vlan_offset = 4;
        switch ( m_ether->getVlanProtocol() ){
        case EthernetHeader::Protocol::IP:
            // IPv4 packet
            ipv4=(IPHeader *)(p+18);
            m_l4 = (uint8_t *)ipv4 + ipv4->getHeaderLength();
            protocol = ipv4->getProtocol();
            break;
        case EthernetHeader::Protocol::IPv6 :
            // IPv6 packet
            ipv6=(IPv6Header *)(p+18);
            m_l4 = (uint8_t *)ipv6 + ipv6->getHeaderLength();
            protocol = ipv6->getNextHdr();
            break;
        default:
        break;
        }
        default:
        break;
    }
    m_protocol =protocol;
    m_ipv4=ipv4;
    m_ipv6=ipv6;

    if ( protocol == 0 ){
        return (false);
    }
    return (true);
}
