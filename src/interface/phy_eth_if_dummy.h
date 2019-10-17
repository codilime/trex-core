#ifndef __PHY_ETH_IF_DUMMY_H__
#define __PHY_ETH_IF_DUMMY_H__

#include "phy_eth_if.h"

// stubs for dummy port
class CPhyEthIFDummy : public CPhyEthIF {
 public:
    CPhyEthIFDummy() {
        m_is_dummy = true;
    }
    void conf_queues() {}
    void configure(uint16_t, uint16_t, const struct rte_eth_conf *) {}
    int dump_fdir_global_stats(FILE *fd) { return 0; }
    int reset_hw_flow_stats() { return 0; }
    int get_flow_stats(rx_per_flow_t *rx_stats, tx_per_flow_t *tx_stats, int min, int max, bool reset) { return 0; }
    int get_flow_stats_payload(rx_per_flow_t *rx_stats, tx_per_flow_t *tx_stats, int min, int max, bool reset) { return 0; }
    void rx_queue_setup(uint16_t, uint16_t, unsigned int, const struct rte_eth_rxconf *, struct rte_mempool *) {}
    void tx_queue_setup(uint16_t, uint16_t, unsigned int, const struct rte_eth_txconf *) {}
    void stop_rx_drop_queue() {}
    void configure_rx_duplicate_rules() {}
    int set_port_rcv_all(bool) { return 0; }
    void start() {}
    void stop() {}
    void disable_flow_control() {}
    void dump_stats(FILE *) {}
    void set_ignore_stats_base(CPreTestStats &) {}
    bool get_extended_stats() { return 0; }
    void update_counters() {}
    void stats_clear() {}
    void flush_rx_queue(void) {}
    void dump_stats_extended(FILE *) {}
    void configure_rss(){}
};

#endif /* __PHY_ETH_IF_DUMMY_H__ */