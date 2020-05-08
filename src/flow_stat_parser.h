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

#ifndef __FLOW_STAT_PARSER_H__
#define __FLOW_STAT_PARSER_H__

#include <arpa/inet.h>
#include "common/Network/Packet/IPHeader.h"
#include "common/Network/Packet/IPv6Header.h"
#include "common/Network/Packet/TcpHeader.h"
#include "mbuf.h"

typedef enum CFlowStatParser_err {
    FSTAT_PARSER_E_OK = 0,
    FSTAT_PARSER_E_TOO_SHORT,
    FSTAT_PARSER_E_SHORT_IP_HDR,
    FSTAT_PARSER_E_VLAN_NOT_SUP,
    FSTAT_PARSER_E_QINQ_NOT_SUP,
    FSTAT_PARSER_E_MPLS_NOT_SUP,
    FSTAT_PARSER_E_UNKNOWN_HDR,
    FSTAT_PARSER_E_VLAN_NEEDED,

} CFlowStatParser_err_t;

// Basic flow stat parser. Imitating HW behavior. It can parse only packets matched by HW fdir rules we define.
// Relevant for xl710/x710, i350, Cisco VIC, Mellanox cards

class CFlowStatParser {
    friend class CFlowStatParserTest;

    enum CFlowStatParser_flags {
      FSTAT_PARSER_VLAN_SUPP   = 0x1,
      FSTAT_PARSER_VLAN_NEEDED = 0x2,
      FSTAT_PARSER_QINQ_SUPP   = 0x4,
      FSTAT_PARSER_MPLS_SUPP   = 0x8,
      FSTAT_PARSER_VXLAN_SKIP  = 0x10,
      FSTAT_PARSER_GRE_SKIP    = 0x20,
      FSTAT_PARSER_UDP_SKIP    = 0x40
    };

  public:
    enum CFlowStatParser_mode {
        FLOW_STAT_PARSER_MODE_HW, // all NICs except Intel 82599
        FLOW_STAT_PARSER_MODE_SW, // --software mode and virtual NICs
        FLOW_STAT_PARSER_MODE_82599,
        FLOW_STAT_PARSER_MODE_82599_vlan,
    };
    CFlowStatParser(CFlowStatParser_mode mode);
    virtual ~CFlowStatParser() {}
    virtual void reset();
    std::string get_error_str(CFlowStatParser_err_t err);
    virtual CFlowStatParser_err_t parse(uint8_t *pkt, uint16_t len);
    virtual uint16_t get_vxlan_payload_offset(uint8_t *pkt, uint16_t len);
    virtual uint16_t get_tun_payload_offset(uint8_t *pkt, uint16_t len);
    void set_vxlan_skip(bool enable){
        if (enable) {
          m_flags |=  FSTAT_PARSER_VXLAN_SKIP;
        }else{
          m_flags &= ~FSTAT_PARSER_VXLAN_SKIP;
        }

    }
    bool get_vxlan_skip() { return ((m_flags & FSTAT_PARSER_VXLAN_SKIP)?true:false); }

    void set_gre_skip(bool enable){
        if (enable) {
          m_flags |=  FSTAT_PARSER_GRE_SKIP;
        }else{
          m_flags &= ~FSTAT_PARSER_GRE_SKIP;
        }

    }
    bool get_gre_skip() { return ((m_flags & FSTAT_PARSER_GRE_SKIP)?true:false); }

    void set_udp_tun_skip(uint32_t port){
        if (port > 0) {
            m_udp_tun_port = port;
            m_flags |=  FSTAT_PARSER_UDP_SKIP;
        }else{
            m_udp_tun_port = 0;
            m_flags &= ~FSTAT_PARSER_UDP_SKIP;
        }

    }
    bool get_udp_tun_skip() { return ((m_flags & FSTAT_PARSER_UDP_SKIP)?true:false); }


    void set_mpls_ethertype(uint32_t label, uint16_t ethertype) {
        m_mpls_ethertype.insert_or_assign(label, ethertype);
    }

    int32_t get_mpls_ethertype(uint32_t label) {
        auto it = m_mpls_ethertype.find(label);
        if (it != m_mpls_ethertype.end())
            return it->second;
        else
            return m_mpls_def_ethertype;
    }

    virtual int get_ip_id(uint32_t &ip_id);
    virtual void set_ip_id(uint32_t ip_id);
    virtual void set_tos_to_cpu();
    virtual int get_l3_proto(uint16_t &proto);
    virtual int get_l4_proto(uint8_t &proto);
    virtual int get_payload_len(uint8_t *p, uint16_t len, uint16_t &payload_len);
    virtual uint16_t get_pkt_size();
    virtual uint8_t get_ttl();
    bool is_fs_latency();
    uint8_t get_protocol();

    uint8_t *get_l3() {
        if (m_ipv4)
            return (uint8_t *)m_ipv4;
        else
            return (uint8_t *)m_ipv6;
    }
    uint8_t * get_l4() {return m_l4;}

    inline bool IsNatInfoPkt(bool &first) {
        if (! m_ipv4 ) {
            return false;
        }

        if (m_l4_proto == IPPROTO_TCP) {
            if ((m_l4 + TCP_HEADER_LEN) > (uint8_t *)m_ipv4 + get_pkt_size()) {
                return false;
            }
            // If we are here, relevant fields from tcp header are inside the packet boundaries
            // We want to handle SYN and SYN+ACK packets
            TCPHeader *tcp = (TCPHeader *)m_l4;
            if (! tcp->getSynFlag())
                return false;

            if (! tcp->getAckFlag()) {
                first = true;
            } else {
                first = false;
            }
            return true;
        } else {
            if ((m_ipv4->getId() & 0x8000) != 0) {
                first = true;
                return true;
            } else {
                return false;
            }
        }
    }

 private:
    char *create_test_pkt(int ip_ver, uint16_t l4_proto, uint8_t ttl
                          , uint32_t ip_id, uint16_t flags, int &pkt_size);
    CFlowStatParser_err_t _parse(uint8_t *p, uint16_t len, uint16_t next_hdr = 0);

    uint16_t get_vxlan_rx_payload_offset(uint8_t *pkt, uint16_t len);
    uint16_t get_tun_rx_payload_offset(uint8_t *pkt, uint16_t len);
    uint16_t get_udp_tun_rx_payload_offset(uint8_t *pkt, uint16_t len);

  protected:
    uint8_t *m_start;
    uint16_t m_len;
    uint16_t m_next_header;
    IPHeader *m_ipv4;
    IPv6Header *m_ipv6;
    uint8_t *m_l4;
    uint8_t m_l4_proto;
    uint32_t m_l4_port;
    uint8_t m_vlan_offset;
    uint16_t m_flags;
    uint32_t m_udp_tun_port;
    uint16_t m_mpls_def_ethertype;
    std::unordered_map<uint32_t, uint16_t> m_mpls_ethertype;
};

class CPassAllParser : public CFlowStatParser {
 public:
 CPassAllParser() : CFlowStatParser (CFlowStatParser::FLOW_STAT_PARSER_MODE_SW) {}
    virtual CFlowStatParser_err_t parse(uint8_t *pkt, uint16_t len);
    //void set_tos_to_cpu() {}
    virtual int get_ip_id(uint32_t &ip_id) { ip_id = 0; return 0;}
    virtual void set_ip_id(uint32_t ip_id){}
    virtual int get_l3_proto(uint16_t &proto){proto = 0; return 0;}
    virtual int get_l4_proto(uint8_t &proto) {proto = 0; return 0;}
    virtual int get_payload_len(uint8_t *p, uint16_t len, uint16_t &payload_len) {payload_len = m_len; return 0;}
};

// Used for latency statefull packets. Need to be merged with above parser
class CSimplePacketParser {
 public:
    CSimplePacketParser(rte_mbuf_t * m){
        m_m = m;
        m_l4 = NULL;
    }
    bool Parse();

    // Check if this packet contains NAT info in TCP ack
    // first - set to true if this is the first packet of the flow. false otherwise.
    //         relevant only if return value is true
    inline bool IsNatInfoPkt(bool &first) {
        if (! m_ipv4 ) {
            return false;
        }

        if (m_ipv4->getProtocol() == IPPROTO_TCP) {
            if (! m_l4 || (m_l4 - rte_pktmbuf_mtod(m_m, uint8_t*) + TCP_HEADER_LEN) > m_m->data_len) {
                return false;
            }
            // If we are here, relevant fields from tcp header are inside the packet boundaries
            // We want to handle SYN and SYN+ACK packets
            TCPHeader *tcp = (TCPHeader *)m_l4;
            if (! tcp->getSynFlag())
                return false;

            if (! tcp->getAckFlag()) {
                first = true;
            } else {
                first = false;
            }
            return true;
        } else {
            if ((m_ipv4->getId() & 0x8000) != 0) {
                first = true;
                return true;
            } else {
                return false;
            }
        }
    }

 public:
    IPHeader *      m_ipv4;
    IPv6Header *    m_ipv6;
    uint8_t         m_protocol;
    uint16_t        m_vlan_offset;
    uint8_t *       m_l4;
 private:
    rte_mbuf_t *    m_m;
};

class CFlowStatParserTest {
    typedef struct {
        CFlowStatParser_err_t m_hw;
        CFlowStatParser_err_t m_sw;
        CFlowStatParser_err_t m_82599;
        CFlowStatParser_err_t m_82599_vlan;
    } CFlowStatParserTest_exp_err_t;

    enum {
        P_OK = 0x1,
        P_BAD = 0x2,
        P82599_OK = 0x4,
        P82599_BAD = 0x8,
        P82599_VLAN_OK = 0x10,
        P82599_VLAN_BAD = 0x20,
        P_SW_OK = 0x40,
        P_SW_BAD = 0x80,
    };

 public:
    int test();

 private:
    int test_one_pkt(const char *name, uint16_t ether_type, uint8_t l4_proto, int vlan_num
                     , CFlowStatParserTest_exp_err_t exp_err);
    int verify_pkt(uint8_t *p, uint16_t pkt_size, uint16_t payload_len, uint32_t ip_id, uint8_t l4_proto
                   , CFlowStatParserTest_exp_err_t exp_err);
    int verify_pkt_one_parser(uint8_t * p, uint16_t pkt_size, uint16_t payload_len, uint32_t ip_id, uint8_t l4_proto
                              , CFlowStatParser &parser, CFlowStatParser_err_t exp_ret);
};

#endif
