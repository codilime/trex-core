#ifndef __PHY_ETH_IF_STATS_H__
#define __PHY_ETH_IF_STATS_H__

#include <rte_ethdev.h>
#include "trex_defs.h"


// These are statistics for packets we send, and do not expect to get back (Like ARP)
// We reduce them from general statistics we report (and report them separately, so we can keep the assumption
// that tx_pkts == rx_pkts and tx_bytes==rx_bytes

class CPhyEthIgnoreStats {
    friend class CPhyEthIF;

 public:
    uint64_t get_rx_arp() {return m_rx_arp;}
    uint64_t get_tx_arp() {return m_tx_arp;}
 private:
    uint64_t ipackets;  /**< Total number of successfully received packets. */
    uint64_t ibytes;    /**< Total number of successfully received bytes. */
    uint64_t opackets;  /**< Total number of successfully transmitted packets.*/
    uint64_t obytes;    /**< Total number of successfully transmitted bytes. */
    uint64_t m_tx_arp;    /**< Total number of successfully transmitted ARP packets */
    uint64_t m_rx_arp;    /**< Total number of successfully received ARP packets */

 private:
    void dump(FILE *fd);
};

class CPhyEthIFStats {
 public:
    uint64_t ipackets;  /**< Total number of successfully received packets. */
    uint64_t ibytes;    /**< Total number of successfully received bytes. */
    uint64_t f_ipackets;  /**< Total number of successfully received packets - filter SCTP*/
    uint64_t f_ibytes;    /**< Total number of successfully received bytes. - filter SCTP */
    uint64_t opackets;  /**< Total number of successfully transmitted packets.*/
    uint64_t obytes;    /**< Total number of successfully transmitted bytes. */
    uint64_t ierrors;   /**< Total number of erroneous received packets. */
    uint64_t oerrors;   /**< Total number of failed transmitted packets. */
    uint64_t imcasts;   /**< Total number of multicast received packets. */
    uint64_t rx_nombuf; /**< Total number of RX mbuf allocation failures. */
    struct rte_eth_stats m_prev_stats;
    uint64_t m_rx_per_flow_pkts [MAX_FLOW_STATS]; // Per flow RX pkts
    uint64_t m_rx_per_flow_bytes[MAX_FLOW_STATS]; // Per flow RX bytes
    // Previous fdir stats values read from driver. Since on xl710 this is 32 bit, we save old value, to handle wrap around.
    uint32_t  m_fdir_prev_pkts [MAX_FLOW_STATS];
    uint32_t  m_fdir_prev_bytes [MAX_FLOW_STATS];
 public:
    void Clear();
    void Dump(FILE *fd);
    void DumpAll(FILE *fd);
};

#endif /* __PHY_ETH_IF_STATS_H__ */