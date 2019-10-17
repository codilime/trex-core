#include "phy_eth_if_stats.h"
#include "hot_section.h"

COLD_FUNC void CPhyEthIFStats::Clear() {
    ipackets = 0;
    ibytes = 0;
    f_ipackets = 0;
    f_ibytes = 0;
    opackets = 0;
    obytes = 0;
    ierrors = 0;
    oerrors = 0;
    imcasts = 0;
    rx_nombuf = 0;
    memset(&m_prev_stats, 0, sizeof(m_prev_stats));
    memset(m_rx_per_flow_pkts, 0, sizeof(m_rx_per_flow_pkts));
    memset(m_rx_per_flow_bytes, 0, sizeof(m_rx_per_flow_bytes));
}

// dump all counters (even ones that equal 0)
void CPhyEthIFStats::DumpAll(FILE *fd) {
#define DP_A4(f) printf(" %-40s : %llu \n",#f, (unsigned long long)f)
#define DP_A(f) if (f) printf(" %-40s : %llu \n",#f, (unsigned long long)f)
    DP_A4(opackets);
    DP_A4(obytes);
    DP_A4(ipackets);
    DP_A4(ibytes);
    DP_A(ierrors);
    DP_A(oerrors);
}

// dump all non zero counters
COLD_FUNC void CPhyEthIFStats::Dump(FILE *fd) {
  DP_A(opackets);
  DP_A(obytes);
  DP_A(f_ipackets);
  DP_A(f_ibytes);
  DP_A(ipackets);
  DP_A(ibytes);
  DP_A(ierrors);
  DP_A(oerrors);
  DP_A(imcasts);
  DP_A(rx_nombuf);
}

COLD_FUNC void CPhyEthIgnoreStats::dump(FILE *fd) {
    DP_A4(opackets);
    DP_A4(obytes);
    DP_A4(ipackets);
    DP_A4(ibytes);
    DP_A4(m_tx_arp);
    DP_A4(m_rx_arp);
}