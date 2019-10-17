#ifndef __PHY_ETH_IF_H__
#define __PHY_ETH_IF_H__

#include <rte_ethdev.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include "stats/phy_eth_if_stats.h"
#include "pre_test.h"
#include "bp_sim.h"
#include "dpdk_port_map.h"
#include "trex_modes.h"

class CPhyEthIF  {
 public:
    CPhyEthIF (){
        m_tvpid          = DPDK_MAP_IVALID_REPID;
        m_repid          = DPDK_MAP_IVALID_REPID;
        m_rx_queue       = 0;
        m_stats_err_cnt  = 0;
        m_is_dummy       = false;
        m_dev_tx_offload_needed =0;
        m_stats.Clear();
    }
    virtual ~CPhyEthIF() {}
    bool Create(tvpid_t  tvpid,
                repid_t  repid);

    void set_rx_queue(uint8_t rx_queue){
        m_rx_queue=rx_queue;
    }
    virtual void conf_queues();

    virtual void configure(uint16_t nb_rx_queue,
                   uint16_t nb_tx_queue,
                   const struct rte_eth_conf *eth_conf);
    virtual int dump_fdir_global_stats(FILE *fd);
    virtual int reset_hw_flow_stats();
    virtual int get_flow_stats(rx_per_flow_t *rx_stats, tx_per_flow_t *tx_stats, int min, int max, bool reset);
    virtual int get_flow_stats_payload(rx_per_flow_t *rx_stats, tx_per_flow_t *tx_stats, int min, int max, bool reset);
    virtual void rx_queue_setup(uint16_t rx_queue_id,
                                uint16_t nb_rx_desc,
                                unsigned int socket_id,
                                const struct rte_eth_rxconf *rx_conf,
                                struct rte_mempool *mb_pool);
    virtual void tx_queue_setup(uint16_t tx_queue_id,
                                uint16_t nb_tx_desc,
                                unsigned int socket_id,
                                const struct rte_eth_txconf *tx_conf);
    virtual void stop_rx_drop_queue();
    virtual void configure_rx_duplicate_rules();
    virtual int set_port_rcv_all(bool is_rcv);
    virtual inline bool is_dummy() { return m_is_dummy; }
    virtual void start();
    virtual void stop();
    virtual void disable_flow_control();
    virtual void dump_stats(FILE *fd);
    virtual void set_ignore_stats_base(CPreTestStats &pre_stats);
    virtual bool get_extended_stats();
    virtual void update_counters();

    virtual void stats_clear();

    tvpid_t             get_tvpid(){
        return (m_tvpid);
    }

    repid_t             get_repid(){
        return (m_repid);
    }

    float get_last_tx_rate(){
        return (m_last_tx_rate);
    }
    float get_last_rx_rate(){
        return (m_last_rx_rate);
    }
    float get_last_tx_pps_rate(){
        return (m_last_tx_pps);
    }
    float get_last_rx_pps_rate(){
        return (m_last_rx_pps);
    }

    CPhyEthIFStats     & get_stats(){
        return ( m_stats );
    }
    CPhyEthIgnoreStats & get_ignore_stats() {
        return m_ignore_stats;
    }
    virtual void HOT_FUNC flush_rx_queue(void);

    inline void HOT_FUNC tx_offload_csum(struct rte_mbuf *m, uint64_t tx_offload) {
        /* assume that l2_len and l3_len in rte_mbuf updated properly */
        uint16_t csum = 0, csum_start = m->l2_len + m->l3_len;

        /* assume that IP pseudo header checksum was already caclulated */
        if (rte_raw_cksum_mbuf(m, csum_start, rte_pktmbuf_pkt_len(m) - csum_start, &csum) < 0)
            return;
        csum = (csum != 0xffff) ? ~csum: csum;

        if (((m->ol_flags & PKT_TX_L4_MASK) == PKT_TX_TCP_CKSUM) &&
            !(tx_offload & DEV_TX_OFFLOAD_TCP_CKSUM)) {
            struct tcp_hdr *tcp_hdr = rte_pktmbuf_mtod_offset(m, struct tcp_hdr *, csum_start);

            tcp_hdr->cksum = csum;
            m->ol_flags &= ~PKT_TX_L4_MASK;     /* PKT_TX_L4_NO_CKSUM is 0 */
        } else if (((m->ol_flags & PKT_TX_L4_MASK) == PKT_TX_UDP_CKSUM) &&
                    !(tx_offload & DEV_TX_OFFLOAD_UDP_CKSUM)) {
            struct udp_hdr *udp_hdr = rte_pktmbuf_mtod_offset(m, struct udp_hdr *, csum_start);

            udp_hdr->dgram_cksum = csum;
            m->ol_flags &= ~PKT_TX_L4_MASK;     /* PKT_TX_L4_NO_CKSUM is 0 */
        }

        if ((m->ol_flags & PKT_TX_IPV4) && (m->ol_flags & PKT_TX_IP_CKSUM) &&
            !(tx_offload & DEV_TX_OFFLOAD_IPV4_CKSUM)) {
            struct ipv4_hdr *iph = rte_pktmbuf_mtod_offset(m, struct ipv4_hdr *, m->l2_len);

            if (!iph->hdr_checksum) {
                iph->hdr_checksum = rte_ipv4_cksum(iph);
                m->ol_flags &= ~PKT_TX_IP_CKSUM;
            }
        }
    }
    inline void HOT_FUNC tx_burst_offload_csum(struct rte_mbuf **tx_pkts, uint16_t nb_pkts, uint64_t tx_offload) {
        uint16_t nb_tx = 0;

        for (nb_tx = 0; nb_tx < nb_pkts; nb_tx++) {
            struct rte_mbuf *m = tx_pkts[nb_tx];

            if (((m->ol_flags & PKT_TX_L4_MASK) == PKT_TX_TCP_CKSUM) ||
                ((m->ol_flags & PKT_TX_L4_MASK) == PKT_TX_UDP_CKSUM)) {
                tx_offload_csum(m, tx_offload);
            }
        }
    }

    inline uint16_t HOT_FUNC tx_burst(uint16_t queue_id, struct rte_mbuf **tx_pkts, uint16_t nb_pkts) {
        if (likely( !m_is_dummy )) {
            if (unlikely(m_dev_tx_offload_needed)) {
                tx_burst_offload_csum(tx_pkts, nb_pkts, m_dev_tx_offload_needed);
            }
            return rte_eth_tx_burst(m_repid, queue_id, tx_pkts, nb_pkts);
        } else {
            for (int i=0; i<nb_pkts;i++) {
                rte_pktmbuf_free(tx_pkts[i]);
            }
            return nb_pkts;
        }
    }
    inline uint16_t  HOT_FUNC rx_burst(uint16_t queue_id, struct rte_mbuf **rx_pkts, uint16_t nb_pkts) {
        if (likely( !m_is_dummy )) {
            return rte_eth_rx_burst(m_repid, queue_id, rx_pkts, nb_pkts);
        } else {
            return 0;
        }
    }


    inline uint32_t pci_reg_read(uint32_t reg_off) {
        assert(!m_is_dummy);
        void *reg_addr;
        uint32_t reg_v;
        reg_addr = (void *)((char *)m_port_attr->get_pci_dev()->mem_resource[0].addr +
                            reg_off);
        reg_v = *((volatile uint32_t *)reg_addr);
        return rte_le_to_cpu_32(reg_v);
    }
    inline void pci_reg_write(uint32_t reg_off,
                              uint32_t reg_v) {
        assert(!m_is_dummy);
        void *reg_addr;

        reg_addr = (void *)((char *)m_port_attr->get_pci_dev()->mem_resource[0].addr +
                            reg_off);
        *((volatile uint32_t *)reg_addr) = rte_cpu_to_le_32(reg_v);
    }
    virtual void dump_stats_extended(FILE *fd);

    const std::vector<std::pair<uint8_t, uint8_t>> & get_core_list();
    TRexPortAttr * get_port_attr() { return m_port_attr; }

    virtual void configure_rss();

private:
    void conf_hardware_astf_rss();
    void conf_multi_rx();


    void _conf_queues(uint16_t tx_qs,
                      uint32_t tx_descs,
                      uint16_t rx_qs,
                      rx_que_desc_t & rx_qs_descs,
                      uint16_t rx_qs_drop_qid,
                      trex_dpdk_rx_distro_mode_t rss_mode,
                      bool in_astf_mode);


private:
    void conf_rx_queues_astf_multi_core();

    void configure_rss_astf(bool is_client,
                           uint16_t numer_of_queues,
                           uint16_t skip_queue);



 private:
    tvpid_t                  m_tvpid;
    repid_t                  m_repid;
    uint8_t                  m_rx_queue;
    uint8_t                  m_dev_tx_offload_needed;
    uint64_t                 m_sw_try_tx_pkt;
    uint64_t                 m_sw_tx_drop_pkt;
    uint32_t                 m_stats_err_cnt;
    CBwMeasure               m_bw_tx;
    CBwMeasure               m_bw_rx;
    CPPSMeasure              m_pps_tx;
    CPPSMeasure              m_pps_rx;
    CPhyEthIFStats           m_stats;
    CPhyEthIgnoreStats       m_ignore_stats;
    TRexPortAttr            *m_port_attr;
    float                    m_last_tx_rate;
    float                    m_last_rx_rate;
    float                    m_last_tx_pps;
    float                    m_last_rx_pps;

    /* holds the core ID list for this port - (core, dir) list*/
    std::vector<std::pair<uint8_t, uint8_t>> m_core_id_list;

 protected:
    bool                     m_is_dummy;

};

#endif /* __PHY_ETH_IF_H__ */