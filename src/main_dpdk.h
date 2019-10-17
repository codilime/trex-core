/*
  Copyright (c) 2015-2017 Cisco Systems, Inc.

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

#ifndef MAIN_DPDK_H
#define MAIN_DPDK_H

#include <rte_ethdev.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include "pre_test.h"
#include "bp_sim.h"
#include "dpdk_port_map.h"
#include "trex_modes.h"
#include "interface/phy_eth_if.h"
#include "stateful_rx_core.h"

#define TREX_NAME "_t-rex-64"

#define MAX_PKT_BURST   32
#define BP_MAX_CORES 48
#define BP_MASTER_AND_LATENCY 2
#define MAX_DPDK_ARGS 50


class CLatencyHWPort : public CPortLatencyHWBase {
public:
    void Create(CPhyEthIF  * p,
                uint8_t tx_queue,
                uint8_t rx_queue){
        m_port=p;
        m_tx_queue_id=tx_queue;
        m_rx_queue_id=rx_queue;
    }

    virtual int tx(rte_mbuf_t *m) {

        apply_hw_vlan(m, m_port->get_tvpid());
        return tx_raw(m);
    }


    virtual int tx_raw(rte_mbuf_t *m) {

        rte_mbuf_t *tx_pkts[2];
        tx_pkts[0] = m;

        uint16_t res=m_port->tx_burst(m_tx_queue_id, tx_pkts, 1);
        if ( res == 0 ) {
            //printf(" queue is full for latency packet !!\n");
            return (-1);

        }

        return 0;
    }


    /* nothing special with HW implementation */
    virtual int tx_latency(rte_mbuf_t *m) {
        return tx(m);
    }

    virtual rte_mbuf_t * rx(){
        rte_mbuf_t * rx_pkts[1];
        uint16_t cnt=m_port->rx_burst(m_rx_queue_id,rx_pkts,1);
        if (cnt) {
            return (rx_pkts[0]);
        }else{
            return (0);
        }
    }


    virtual uint16_t rx_burst(struct rte_mbuf **rx_pkts,
                              uint16_t nb_pkts){
        uint16_t cnt=m_port->rx_burst(m_rx_queue_id,rx_pkts,nb_pkts);
        return (cnt);
    }


private:
    CPhyEthIF  * m_port;
    uint8_t      m_tx_queue_id ;
    uint8_t      m_rx_queue_id;
};

class CLatencyVmPort : public CPortLatencyHWBase {
public:
    void Create(uint8_t port_index,
                CNodeRing *ring,
                CLatencyManager *mgr,
                CPhyEthIF  *p,
                bool disable_rx_read) {

        m_dir        = (port_index % 2);
        m_ring_to_dp = ring;
        m_mgr        = mgr;
        m_port       = p;
        m_disable_rx = disable_rx_read;
    }


    virtual int tx(rte_mbuf_t *m) {
        return tx_common(m, false, true);
    }

    virtual int tx_raw(rte_mbuf_t *m) {
        return tx_common(m, false, false);
    }

    virtual int tx_latency(rte_mbuf_t *m) {
        return tx_common(m, true, true);
    }

    virtual rte_mbuf_t * rx() {
        if (m_disable_rx==false){
            rte_mbuf_t * rx_pkts[1];
            uint16_t cnt = m_port->rx_burst(0, rx_pkts, 1);
            if (cnt) {
                return (rx_pkts[0]);
            } else {
                return (0);
            }
        }else{
            return (0);
        }
    }

    virtual uint16_t rx_burst(struct rte_mbuf **rx_pkts, uint16_t nb_pkts) {
        if (m_disable_rx==false){
            uint16_t cnt = m_port->rx_burst(0, rx_pkts, nb_pkts);
            return (cnt);
        }else{
            return (0);
        }
    }

private:
      virtual int tx_common(rte_mbuf_t *m, bool fix_timestamp, bool add_hw_vlan) {

        if (add_hw_vlan) {
            apply_hw_vlan(m, m_port->get_tvpid());
        }

        /* allocate node */
        CGenNodeLatencyPktInfo *node=(CGenNodeLatencyPktInfo * )CGlobalInfo::create_node();
        if (!node) {
            return (-1);
        }

        node->m_msg_type = CGenNodeMsgBase::LATENCY_PKT;
        node->m_dir      = m_dir;
        node->m_pkt      = m;

        if (fix_timestamp) {
            node->m_latency_offset = m_mgr->get_latency_header_offset();
            node->m_update_ts = 1;
        } else {
            node->m_update_ts = 0;
        }

        if ( m_ring_to_dp->Enqueue((CGenNode*)node) != 0 ){
            CGlobalInfo::free_node((CGenNode *)node);
            return (-1);
        }

        return (0);
    }

    CPhyEthIF                       *m_port;
    uint8_t                          m_dir;
    bool                             m_disable_rx; /* TBD need to read from remote queue */
    CNodeRing                       *m_ring_to_dp;   /* ring dp -> latency thread */
    CLatencyManager                 *m_mgr;
};

class CPerPortStats {
public:
    uint64_t opackets;
    uint64_t obytes;
    uint64_t ipackets;
    uint64_t ibytes;
    uint64_t ierrors;
    uint64_t oerrors;
    tx_per_flow_t m_tx_per_flow[MAX_FLOW_STATS + MAX_FLOW_STATS_PAYLOAD];
    tx_per_flow_t m_prev_tx_per_flow[MAX_FLOW_STATS + MAX_FLOW_STATS_PAYLOAD];

    float     m_total_tx_bps;
    float     m_total_tx_pps;

    float     m_total_rx_bps;
    float     m_total_rx_pps;

    float     m_cpu_util;
    bool      m_link_up = true;
    bool      m_link_was_down = false;
};

class CGlobalStats {
public:
    enum DumpFormat {
        dmpSTANDARD,
        dmpTABLE
    };

    uint64_t  m_total_tx_pkts;
    uint64_t  m_total_rx_pkts;
    uint64_t  m_total_tx_bytes;
    uint64_t  m_total_rx_bytes;

    uint64_t  m_total_alloc_error;
    uint64_t  m_total_queue_full;
    uint64_t  m_total_queue_drop;

    uint64_t  m_total_clients;
    uint64_t  m_total_servers;
    uint64_t  m_active_sockets;

    uint64_t  m_total_nat_time_out;
    uint64_t  m_total_nat_time_out_wait_ack;
    uint64_t  m_total_nat_no_fid  ;
    uint64_t  m_total_nat_active  ;
    uint64_t  m_total_nat_syn_wait;
    uint64_t  m_total_nat_open    ;
    uint64_t  m_total_nat_learn_error    ;

    CPerTxthreadTemplateInfo m_template;

    float     m_socket_util;

    float m_platform_factor;
    float m_tx_bps;
    float m_rx_bps;
    float m_tx_pps;
    float m_rx_pps;
    float m_tx_cps;
    float m_tx_expected_cps;
    float m_tx_expected_pps;
    float m_tx_expected_bps;
    float m_rx_drop_bps;
    float m_active_flows;
    float m_open_flows;
    float m_cpu_util;
    float m_cpu_util_raw;
    float m_rx_cpu_util;
    float m_rx_core_pps;
    float m_bw_per_core;
    uint8_t m_threads;

    uint32_t      m_num_of_ports;
    CPerPortStats m_port[TREX_MAX_PORTS];
public:
    void Dump(FILE *fd,DumpFormat mode);
    void DumpAllPorts(FILE *fd);

    void dump_json(std::string & json, bool baseline);

    void global_stats_to_json(Json::Value &output);
    void port_stats_to_json(Json::Value &output, uint8_t port_id);

private:
    bool is_dump_nat();

private:
    std::string get_field(const char *name, float &f);
    std::string get_field(const char *name, uint64_t &f);
    std::string get_field_port(int port, const char *name, float &f);
    std::string get_field_port(int port, const char *name, uint64_t &f);

};

class CCorePerPort  {
public:
    CCorePerPort (){
        m_tx_queue_id=0;
        m_len=0;
        int i;
        for (i=0; i<MAX_PKT_BURST; i++) {
            m_table[i]=0;
        }
        m_port=0;
    }
    uint8_t                 m_tx_queue_id;
    uint8_t                 m_tx_queue_id_lat; // q id for tx of latency pkts
    uint16_t                m_len;
    rte_mbuf_t *            m_table[MAX_PKT_BURST];
    CPhyEthIF  *            m_port;
};


#define MAX_MBUF_CACHE 100


/* per core/gbe queue port for trasmitt */
class CCoreEthIF : public CVirtualIF {
public:
    enum {
     INVALID_Q_ID = 255
    };

public:

    CCoreEthIF(){
        m_mbuf_cache=0;
    }

    bool Create(uint8_t             core_id,
                uint8_t            tx_client_queue_id,
                CPhyEthIF  *        tx_client_port,
                uint8_t            tx_server_queue_id,
                CPhyEthIF  *        tx_server_port,
                uint8_t             tx_q_id_lat);
    void Delete();

    virtual int open_file(std::string file_name){
        return (0);
    }

    virtual int close_file(void){
        return (flush_tx_queue());
    }
    __attribute__ ((noinline)) int send_node_flow_stat(rte_mbuf *m, CGenNodeStateless * node_sl
                                                       , CCorePerPort *  lp_port
                                                       , CVirtualIFPerSideStats  * lp_stats, bool is_const);
    virtual int send_node(CGenNode * node);
    virtual void send_one_pkt(pkt_dir_t dir, rte_mbuf_t *m);
    virtual int flush_tx_queue(void);
    __attribute__ ((noinline)) void handle_slowpath_features(CGenNode *node, rte_mbuf_t *m, uint8_t *p, pkt_dir_t dir);

    bool redirect_to_rx_core(pkt_dir_t   dir,rte_mbuf_t * m);

    virtual int update_mac_addr_from_global_cfg(pkt_dir_t       dir, uint8_t * p);

    virtual pkt_dir_t port_id_to_dir(uint8_t port_id);
    void GetCoreCounters(CVirtualIFPerSideStats *stats);
    void DumpCoreStats(FILE *fd);
    void DumpIfStats(FILE *fd);
    static void DumpIfCfgHeader(FILE *fd);
    void DumpIfCfg(FILE *fd);

    socket_id_t get_socket_id(){
        return ( CGlobalInfo::m_socket.port_to_socket( m_ports[0].m_port->get_tvpid() ) );
    }

    const CCorePerPort * get_ports() {
        return m_ports;
    }

protected:

    int send_burst(CCorePerPort * lp_port,
                   uint16_t len,
                   CVirtualIFPerSideStats  * lp_stats);
    int send_pkt(CCorePerPort * lp_port,
                 rte_mbuf_t *m,
                 CVirtualIFPerSideStats  * lp_stats);
    int send_pkt_lat(CCorePerPort * lp_port,
                 rte_mbuf_t *m,
                 CVirtualIFPerSideStats  * lp_stats);

protected:
    uint8_t      m_core_id;
    uint16_t     m_mbuf_cache;
    CCorePerPort m_ports[CS_NUM]; /* each core has 2 tx queues 1. client side and server side */
    CNodeRing *  m_ring_to_rx;

} __rte_cache_aligned;

class CCoreEthIFStateless : public CCoreEthIF {
public:
    virtual int send_node_flow_stat(rte_mbuf *m, CGenNodeStateless * node_sl, CCorePerPort *  lp_port
                                    , CVirtualIFPerSideStats  * lp_stats, bool is_const);

     /* works in sw multi core only, need to verify it */
    virtual uint16_t rx_burst(pkt_dir_t dir,
                              struct rte_mbuf **rx_pkts,
                              uint16_t nb_pkts);
    /**
     * fast path version
     */
    virtual int send_node(CGenNode *node);

    /**
     * slow path version
     */
    virtual int send_node_service_mode(CGenNode *node);

protected:
    template <bool SERVICE_MODE> inline int send_node_common(CGenNode *no);

    inline rte_mbuf_t * generate_node_pkt(CGenNodeStateless *node_sl)   __attribute__ ((always_inline));
    inline int send_node_packet(CGenNodeStateless      *node_sl,
                                rte_mbuf_t             *m,
                                CCorePerPort           *lp_port,
                                CVirtualIFPerSideStats *lp_stats)   __attribute__ ((always_inline));

    rte_mbuf_t * generate_slow_path_node_pkt(CGenNodeStateless *node_sl);

public:
    void set_rx_queue_id(uint16_t client_qid,
                         uint16_t server_qid){
        m_rx_queue_id[CLIENT_SIDE]=client_qid;
        m_rx_queue_id[SERVER_SIDE]=server_qid;
    }
public:
    uint16_t     m_rx_queue_id[CS_NUM]; 
};

class CCoreEthIFTcp : public CCoreEthIF {
public:
    CCoreEthIFTcp() {
        m_rx_queue_id[CLIENT_SIDE]=0xffff;
        m_rx_queue_id[SERVER_SIDE]=0xffff;
    }

    uint16_t     rx_burst(pkt_dir_t dir,
                          struct rte_mbuf **rx_pkts,
                          uint16_t nb_pkts);

    virtual int send_node(CGenNode *node);

    void set_rx_queue_id(uint16_t client_qid,
                         uint16_t server_qid){
        m_rx_queue_id[CLIENT_SIDE]=client_qid;
        m_rx_queue_id[SERVER_SIDE]=server_qid;
    }
public:
    uint16_t     m_rx_queue_id[CS_NUM]; 
};

// Because it is difficult to move CGlobalTRex into this h file, defining interface class to it
class CGlobalTRexInterface  {
 public:
    CPhyEthIF *get_ports(uint8_t &port_num);
};

bool fill_pci_dev(struct rte_eth_dev_info *dev_info, struct rte_pci_device* pci_dev);
void wait_x_sec(int sec);

typedef uint8_t tvpid_t; /* port ID of trex 0,1,2,3 up to MAX_PORTS*/
typedef uint8_t repid_t; /* DPDK port id  */

inline int get_is_rx_thread_enabled() {
    return ((CGlobalInfo::m_options.is_rx_enabled() || get_is_interactive()) ?1:0);
}

COLD_FUNC void get_dpdk_drv_params(CTrexDpdkParams &dpdk_p);
COLD_FUNC void  dump_dpdk_devices(void);
extern CPlatformYamlInfo global_platform_cfg_info;
extern CPciPorts port_map;

#endif
