#include "phy_eth_if.h"
#include "ixgbe_type.h"
#include "main_dpdk.h"
#include "drivers/trex_driver_base.h"
#include "trex_global_object.h"

#define MY_REG(a) {a,(char *)#a}

const static uint8_t server_rss_key[] = {
 0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2,
 0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
 0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4,
 0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
 0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,

 0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2,
 0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
 0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4,
 0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
 0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
};

const static uint8_t client_rss_key[] = {
 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0,
 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0,

 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,

};

COLD_FUNC static rte_mempool_t* get_rx_mem_pool(int socket_id) {
    CTrexDpdkParams dpdk_p;
    get_dpdk_drv_params(dpdk_p);

    switch(dpdk_p.rx_mbuf_type) {
    case MBUF_9k:
        return CGlobalInfo::m_mem_pool[socket_id].m_mbuf_pool_9k;
    case MBUF_2048:
        return CGlobalInfo::m_mem_pool[socket_id].m_mbuf_pool_2048;
    default:
        fprintf(stderr, "Internal error: Wrong rx_mem_pool");
        assert(0);
        return nullptr;
    }
}


// Clear the RX queue of an interface, dropping all packets
void CPhyEthIF::flush_rx_queue(void){

    rte_mbuf_t * rx_pkts[32];
    int j=0;
    uint16_t cnt=0;

    while (true) {
        j++;
        cnt = rx_burst(m_rx_queue,rx_pkts,32);
        if ( cnt ) {
            int i;
            for (i=0; i<(int)cnt;i++) {
                rte_mbuf_t * m=rx_pkts[i];
                /*printf("rx--\n");
                  rte_pktmbuf_dump(stdout,m, rte_pktmbuf_pkt_len(m));*/
                rte_pktmbuf_free(m);
            }
        }
        if ( ((cnt==0) && (j>10)) || (j>15) ) {
            break;
        }
    }
    if (cnt>0) {
        printf(" Warning can't flush rx-queue for port %d \n",(int)m_tvpid);
    }
}

typedef struct cnt_name_ {
    uint32_t offset;
    char * name;
}cnt_name_t;

COLD_FUNC void CPhyEthIF::dump_stats_extended(FILE *fd){

    cnt_name_t reg[]={
        MY_REG(IXGBE_GPTC), /* total packet */
        MY_REG(IXGBE_GOTCL), /* total bytes */
        MY_REG(IXGBE_GOTCH),

        MY_REG(IXGBE_GPRC),
        MY_REG(IXGBE_GORCL),
        MY_REG(IXGBE_GORCH),



        MY_REG(IXGBE_RXNFGPC),
        MY_REG(IXGBE_RXNFGBCL),
        MY_REG(IXGBE_RXNFGBCH),
        MY_REG(IXGBE_RXDGPC  ),
        MY_REG(IXGBE_RXDGBCL ),
        MY_REG(IXGBE_RXDGBCH  ),
        MY_REG(IXGBE_RXDDGPC ),
        MY_REG(IXGBE_RXDDGBCL ),
        MY_REG(IXGBE_RXDDGBCH  ),
        MY_REG(IXGBE_RXLPBKGPC ),
        MY_REG(IXGBE_RXLPBKGBCL),
        MY_REG(IXGBE_RXLPBKGBCH ),
        MY_REG(IXGBE_RXDLPBKGPC ),
        MY_REG(IXGBE_RXDLPBKGBCL),
        MY_REG(IXGBE_RXDLPBKGBCH ),
        MY_REG(IXGBE_TXDGPC      ),
        MY_REG(IXGBE_TXDGBCL     ),
        MY_REG(IXGBE_TXDGBCH     ),
        MY_REG(IXGBE_FDIRUSTAT ),
        MY_REG(IXGBE_FDIRFSTAT ),
        MY_REG(IXGBE_FDIRMATCH ),
        MY_REG(IXGBE_FDIRMISS )

    };
    fprintf (fd," extended counters \n");
    int i;
    for (i=0; i<sizeof(reg)/sizeof(reg[0]); i++) {
        cnt_name_t *lp=&reg[i];
        uint32_t c=pci_reg_read(lp->offset);
        // xl710 bug. Counter values are -559038737 when they should be 0
        if (c && c != -559038737 ) {
            fprintf (fd," %s  : %d \n",lp->name,c);
        }
    }
}

COLD_FUNC void CPhyEthIF::configure(uint16_t nb_rx_queue,
                          uint16_t nb_tx_queue,
                          const struct rte_eth_conf *eth_conf){
    int ret;
    ret = rte_eth_dev_configure(m_repid,
                                nb_rx_queue,
                                nb_tx_queue,
                                eth_conf);

    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Cannot configure device: "
                 "err=%d, port=%u\n",
                 ret, m_repid);

    /* get device info */
    const struct rte_eth_dev_info *m_dev_info = m_port_attr->get_dev_info();

    if (CGlobalInfo::m_options.preview.getChecksumOffloadEnable()) {
        /* check if the device supports TCP and UDP checksum offloading */
        if ((m_dev_info->tx_offload_capa & DEV_TX_OFFLOAD_UDP_CKSUM) == 0) {
            rte_exit(EXIT_FAILURE, "Device does not support UDP checksum offload: "
                     "port=%u\n",
                     m_repid);
        }
        if ((m_dev_info->tx_offload_capa & DEV_TX_OFFLOAD_TCP_CKSUM) == 0) {
            rte_exit(EXIT_FAILURE, "Device does not support TCP checksum offload: "
                     "port=%u\n",
                     m_repid);
        }
    }
}

/*
  rx-queue 0 is the default queue. All traffic not going to queue 1
  will be dropped as queue 0 is disabled
  rx-queue 1 - Latency measurement packets and other features that need software processing will go here.
*/
COLD_FUNC void CPhyEthIF::configure_rx_duplicate_rules(){
    if ( get_dpdk_mode()->is_hardware_filter_needed() ){
        get_ex_drv()->configure_rx_filter_rules(this);
    }
}

COLD_FUNC int CPhyEthIF::set_port_rcv_all(bool is_rcv) {
    if ( get_dpdk_mode()->is_hardware_filter_needed() ){
        get_ex_drv()->set_rcv_all(this, is_rcv);
    }
    return 0;
}

COLD_FUNC void CPhyEthIF::stop_rx_drop_queue() {
    CDpdkModeBase * dpdk_mode = get_dpdk_mode();
    if ( dpdk_mode->is_drop_rx_queue_needed() ) {
        get_ex_drv()->stop_queue(this, MAIN_DPDK_DROP_Q);
    }
}

COLD_FUNC void CPhyEthIF::rx_queue_setup(uint16_t rx_queue_id,
                                        uint16_t nb_rx_desc,
                                        unsigned int socket_id,
                                        const struct rte_eth_rxconf *rx_conf,
                                        struct rte_mempool *mb_pool) {

  int ret = rte_eth_rx_queue_setup(m_repid, rx_queue_id, nb_rx_desc, socket_id,
                                   rx_conf, mb_pool);
  if (ret < 0)
    rte_exit(EXIT_FAILURE,
             "rte_eth_rx_queue_setup: "
             "err=%d, port=%u\n",
             ret, m_repid);
}

COLD_FUNC void CPhyEthIF::tx_queue_setup(uint16_t tx_queue_id,
                               uint16_t nb_tx_desc,
                               unsigned int socket_id,
                               const struct rte_eth_txconf *tx_conf){

    int ret = rte_eth_tx_queue_setup( m_repid,
                                      tx_queue_id,
                                      nb_tx_desc,
                                      socket_id,
                                      tx_conf);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup: "
                 "err=%d, port=%u queue=%u\n",
                 ret, m_repid, tx_queue_id);

}

COLD_FUNC void CPhyEthIF::stop(){
    if (CGlobalInfo::m_options.preview.getCloseEnable()) {
        rte_eth_dev_stop(m_repid);
        rte_eth_dev_close(m_repid);
    }
}

#define DEV_OFFLOAD_CAPA    (DEV_TX_OFFLOAD_IPV4_CKSUM | DEV_TX_OFFLOAD_UDP_CKSUM | DEV_TX_OFFLOAD_TCP_CKSUM)

COLD_FUNC void CPhyEthIF::start(){

    const struct rte_eth_dev_info *m_dev_info = m_port_attr->get_dev_info();

    if ((m_dev_info->tx_offload_capa & DEV_OFFLOAD_CAPA) != DEV_OFFLOAD_CAPA ){
        m_dev_tx_offload_needed = DEV_TX_OFFLOAD_VLAN_INSERT; /* make everyting by software, deriver do not report the right capability e.g. vxnet3 does not support TCP/UDP  */
    }else{
        m_dev_tx_offload_needed = 0;
    }

    get_ex_drv()->clear_extended_stats(this);

    int ret;

    m_bw_tx.reset();
    m_bw_rx.reset();

    m_stats.Clear();
    int i;
    for (i=0;i<10; i++ ) {
        ret = rte_eth_dev_start(m_repid);
        if (ret==0) {
            return;
        }
        delay(1000);
    }
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "rte_eth_dev_start: "
                 "err=%d, port=%u\n",
                 ret, m_repid);

}

// Disabling flow control on interface
COLD_FUNC void CPhyEthIF::disable_flow_control() {
  int ret;
  // see trex-64 issue with loopback on the same NIC
  struct rte_eth_fc_conf fc_conf;
  memset(&fc_conf, 0, sizeof(fc_conf));
  fc_conf.mode = RTE_FC_NONE;
  fc_conf.autoneg = 1;
  fc_conf.pause_time = 100;
  int i;
  for (i = 0; i < 5; i++) {
    ret = rte_eth_dev_flow_ctrl_set(m_repid, &fc_conf);
    if (ret == 0) {
      break;
    }
    delay(1000);
  }
  if (ret < 0)
    rte_exit(EXIT_FAILURE,
             "rte_eth_dev_flow_ctrl_set: "
             "err=%d, port=%u\n probably link is down. Please check your link "
             "activity, or skip flow-control disabling, using: "
             "--no-flow-control-change option\n",
             ret, m_repid);
}

int CPhyEthIF::dump_fdir_global_stats(FILE *fd) {
    return get_ex_drv()->dump_fdir_global_stats(this, fd);
}

void dump_hw_state(FILE *fd,struct ixgbe_hw_stats *hs ){

#define DP_A1(f) if (hs->f) fprintf(fd," %-40s : %llu \n",#f, (unsigned long long)hs->f)
#define DP_A2(f,m) for (i=0;i<m; i++) { if (hs->f[i]) fprintf(fd," %-40s[%d] : %llu \n",#f,i, (unsigned long long)hs->f[i]); }
    int i;

    //for (i=0;i<8; i++) { if (hs->mpc[i]) fprintf(fd," %-40s[%d] : %llu \n","mpc",i,hs->mpc[i]); }
    DP_A2(mpc,8);
    DP_A1(crcerrs);
    DP_A1(illerrc);
    //DP_A1(errbc);
    DP_A1(mspdc);
    DP_A1(mpctotal);
    DP_A1(mlfc);
    DP_A1(mrfc);
    DP_A1(rlec);
    //DP_A1(lxontxc);
    //DP_A1(lxonrxc);
    //DP_A1(lxofftxc);
    //DP_A1(lxoffrxc);
    //DP_A2(pxontxc,8);
    //DP_A2(pxonrxc,8);
    //DP_A2(pxofftxc,8);
    //DP_A2(pxoffrxc,8);

    //DP_A1(prc64);
    //DP_A1(prc127);
    //DP_A1(prc255);
    // DP_A1(prc511);
    //DP_A1(prc1023);
    //DP_A1(prc1522);

    DP_A1(gprc);
    DP_A1(bprc);
    DP_A1(mprc);
    DP_A1(gptc);
    DP_A1(gorc);
    DP_A1(gotc);
    DP_A2(rnbc,8);
    DP_A1(ruc);
    DP_A1(rfc);
    DP_A1(roc);
    DP_A1(rjc);
    DP_A1(mngprc);
    DP_A1(mngpdc);
    DP_A1(mngptc);
    DP_A1(tor);
    DP_A1(tpr);
    DP_A1(tpt);
    DP_A1(ptc64);
    DP_A1(ptc127);
    DP_A1(ptc255);
    DP_A1(ptc511);
    DP_A1(ptc1023);
    DP_A1(ptc1522);
    DP_A1(mptc);
    DP_A1(bptc);
    DP_A1(xec);
    DP_A2(qprc,16);
    DP_A2(qptc,16);
    DP_A2(qbrc,16);
    DP_A2(qbtc,16);
    DP_A2(qprdc,16);
    DP_A2(pxon2offc,8);
    DP_A1(fdirustat_add);
    DP_A1(fdirustat_remove);
    DP_A1(fdirfstat_fadd);
    DP_A1(fdirfstat_fremove);
    DP_A1(fdirmatch);
    DP_A1(fdirmiss);
    DP_A1(fccrc);
    DP_A1(fclast);
    DP_A1(fcoerpdc);
    DP_A1(fcoeprc);
    DP_A1(fcoeptc);
    DP_A1(fcoedwrc);
    DP_A1(fcoedwtc);
    DP_A1(fcoe_noddp);
    DP_A1(fcoe_noddp_ext_buff);
    DP_A1(ldpcec);
    DP_A1(pcrc8ec);
    DP_A1(b2ospc);
    DP_A1(b2ogprc);
    DP_A1(o2bgptc);
    DP_A1(o2bspc);
}

COLD_FUNC void CPhyEthIF::set_ignore_stats_base(CPreTestStats &pre_stats) {
    // reading m_stats, so drivers saving prev in m_stats will be updated.
    // Actually, we want m_stats to be cleared
    
    /* block until this succeeds */
    while (!get_extended_stats()) {
        delay(10);
    }
    
    m_ignore_stats.ipackets = m_stats.ipackets;
    m_ignore_stats.ibytes = m_stats.ibytes;
    m_ignore_stats.opackets = m_stats.opackets;
    m_ignore_stats.obytes = m_stats.obytes;
    m_stats.ipackets = 0;
    m_stats.opackets = 0;
    m_stats.ibytes = 0;
    m_stats.obytes = 0;

    m_ignore_stats.m_tx_arp = pre_stats.m_tx_arp;
    m_ignore_stats.m_rx_arp = pre_stats.m_rx_arp;

    if (isVerbose(2)) {
        fprintf(stdout, "Pre test statistics for port %d\n", m_tvpid);
        m_ignore_stats.dump(stdout);
    }
}

COLD_FUNC void CPhyEthIF::dump_stats(FILE *fd){

    update_counters();

    fprintf(fd,"port : %d \n",(int)m_tvpid);
    fprintf(fd,"------------\n");
    m_stats.DumpAll(fd);
    //m_stats.Dump(fd);
    printf (" Tx : %.1fMb/sec  \n",m_last_tx_rate);
    //printf (" Rx : %.1fMb/sec  \n",m_last_rx_rate);
}

COLD_FUNC void CPhyEthIF::stats_clear(){
    rte_eth_stats_reset(m_repid);
    m_stats.Clear();
}


COLD_FUNC void CPhyEthIF::configure_rss_astf(bool is_client,
                                   uint16_t numer_of_queues,
                                   uint16_t skip_queue){ 

    struct rte_eth_dev_info dev_info;

    rte_eth_dev_info_get(m_repid,&dev_info);
    if (dev_info.reta_size == 0) {
        printf("ERROR driver does not support RSS table configuration for accurate latency measurement, \n");
        printf("You must add the flag --software to CLI \n");
        exit(1);
        return;
    }

    int reta_conf_size = std::max(1, dev_info.reta_size / RTE_RETA_GROUP_SIZE);

    struct rte_eth_rss_reta_entry64 reta_conf[reta_conf_size];

    uint16_t skip = 0;
    uint16_t q;
    uint16_t indx=0;
    for (int j = 0; j < reta_conf_size; j++) {
        reta_conf[j].mask = ~0ULL;
        for (int i = 0; i < RTE_RETA_GROUP_SIZE; i++) {
            while (true) {
                q=(indx + skip) % numer_of_queues;
                if (q != skip_queue) {
                    break;
                }
                skip += 1;
            }
            reta_conf[j].reta[i] = q;
            indx++;
        }
    }
    assert(rte_eth_dev_rss_reta_update(m_repid, &reta_conf[0], dev_info.reta_size)==0);

    #ifdef RSS_DEBUG
     rte_eth_dev_rss_reta_query(m_repid, &reta_conf[0], dev_info.reta_size);
     int j; int i;

     printf(" RSS port  %d \n",m_tvpid);
     /* verification */
     for (j = 0; j < reta_conf_size; j++) {
         for (i = 0; i<RTE_RETA_GROUP_SIZE; i++) {
             printf(" R %d  %d \n",(j*RTE_RETA_GROUP_SIZE+i),reta_conf[j].reta[i]);
         }
     }
    #endif
}



COLD_FUNC void CPhyEthIF::configure_rss(){
    trex_dpdk_rx_distro_mode_t rss_mode = 
         get_dpdk_mode()->get_rx_distro_mode();

    if ( rss_mode == ddRX_DIST_ASTF_HARDWARE_RSS ){
        CTrexDpdkParams dpdk_p;
        get_dpdk_drv_params(dpdk_p);

        configure_rss_astf(false,
                           dpdk_p.get_total_rx_queues(),
                           MAIN_DPDK_RX_Q);
    }
}

COLD_FUNC void CPhyEthIF::conf_multi_rx() {
    const struct rte_eth_dev_info *dev_info = m_port_attr->get_dev_info();
    uint8_t hash_key_size;

     if ( dev_info->hash_key_size==0 ) {
          hash_key_size = 40; /* for mlx5 */
        } else {
          hash_key_size = dev_info->hash_key_size;
     }

    g_trex.m_port_cfg.m_port_conf.rxmode.mq_mode = ETH_MQ_RX_RSS;

    struct rte_eth_rss_conf *lp_rss = 
        &g_trex.m_port_cfg.m_port_conf.rx_adv_conf.rss_conf;

    if (dev_info->flow_type_rss_offloads){
        lp_rss->rss_hf = (dev_info->flow_type_rss_offloads & (ETH_RSS_NONFRAG_IPV4_TCP |
                         ETH_RSS_NONFRAG_IPV4_UDP |
                         ETH_RSS_NONFRAG_IPV6_TCP |
                         ETH_RSS_NONFRAG_IPV6_UDP));
        lp_rss->rss_key =  (uint8_t*)&server_rss_key[0];
    }else{                 
        lp_rss->rss_key =0;
    }
    lp_rss->rss_key_len = hash_key_size;
}

COLD_FUNC void CPhyEthIF::conf_hardware_astf_rss() {

    const struct rte_eth_dev_info *dev_info = m_port_attr->get_dev_info();

    uint8_t hash_key_size;
    #ifdef RSS_DEBUG
    printf("reta_size : %d \n", dev_info->reta_size);
    printf("hash_key  : %d \n", dev_info->hash_key_size);
    #endif

    if ( dev_info->hash_key_size==0 ) {
        hash_key_size = 40; /* for mlx5 */
    } else {
        hash_key_size = dev_info->hash_key_size;
    }

    if (!rte_eth_dev_filter_supported(m_repid, RTE_ETH_FILTER_HASH)) {
        // Setup HW to use the TOEPLITZ hash function as an RSS hash function
        struct rte_eth_hash_filter_info info = {};
        info.info_type = RTE_ETH_HASH_FILTER_GLOBAL_CONFIG;
        info.info.global_conf.hash_func = RTE_ETH_HASH_FUNCTION_TOEPLITZ;
        if (rte_eth_dev_filter_ctrl(m_repid, RTE_ETH_FILTER_HASH,
                                    RTE_ETH_FILTER_SET, &info) < 0) {
            printf(" ERROR cannot set hash function on a port %d \n",m_repid);
            exit(1);
        }
    }
    /* set reta_mask, for now it is ok to set one value to all ports */
    uint8_t reta_mask=(uint8_t)(min(dev_info->reta_size,(uint16_t)256)-1);
    if (CGlobalInfo::m_options.m_reta_mask==0){
        CGlobalInfo::m_options.m_reta_mask = reta_mask ;
    }else{
        if (CGlobalInfo::m_options.m_reta_mask != reta_mask){
            printf("ERROR reta_mask should be the same to all nics \n!");
            exit(1);
        }
    }
    g_trex.m_port_cfg.m_port_conf.rxmode.mq_mode = ETH_MQ_RX_RSS;
    struct rte_eth_rss_conf *lp_rss =&g_trex.m_port_cfg.m_port_conf.rx_adv_conf.rss_conf;
    lp_rss->rss_hf = ETH_RSS_NONFRAG_IPV4_TCP |
                     ETH_RSS_NONFRAG_IPV4_UDP |
                     ETH_RSS_NONFRAG_IPV6_TCP |
                     ETH_RSS_NONFRAG_IPV6_UDP;

    bool is_client_side = ((get_tvpid()%2==0)?true:false);
    if (is_client_side) {
        lp_rss->rss_key =  (uint8_t*)&client_rss_key[0];
    }else{
        lp_rss->rss_key =  (uint8_t*)&server_rss_key[0];
    }
    lp_rss->rss_key_len = hash_key_size;
    
}


COLD_FUNC void CPhyEthIF::_conf_queues(uint16_t tx_qs,
                             uint32_t tx_descs,
                             uint16_t rx_qs,
                             rx_que_desc_t & rx_qs_descs,
                             uint16_t rx_qs_drop_qid,
                             trex_dpdk_rx_distro_mode_t rss_mode,
                             bool in_astf_mode) {

    socket_id_t socket_id = CGlobalInfo::m_socket.port_to_socket((port_id_t)m_tvpid);
    assert(CGlobalInfo::m_mem_pool[socket_id].m_mbuf_pool_2048);
    const struct rte_eth_dev_info *dev_info = m_port_attr->get_dev_info();

    switch (rss_mode) {
    case ddRX_DIST_NONE:
        break;
    case ddRX_DIST_ASTF_HARDWARE_RSS:
        conf_hardware_astf_rss();
        break;
    case ddRX_DIST_BEST_EFFORT:
        conf_multi_rx();
        break;
    case ddRX_DIST_FLOW_BASED:
        assert(0);
        break;
    default:
        assert(0);
    }

    /* configure tx, rx ports with right dpdk hardware  */
    port_cfg_t & cfg = g_trex.m_port_cfg;
    struct rte_eth_conf  & eth_cfg = g_trex.m_port_cfg.m_port_conf;

    uint64_t &tx_offloads = eth_cfg.txmode.offloads;
    tx_offloads = cfg.tx_offloads.common_best_effort;

    if ( in_astf_mode ) {
        tx_offloads |= cfg.tx_offloads.astf_best_effort;
    }

    /* we don't want to enable this in Stateless as mlx5 will have a big performance effect
    other driver enable this without asking  */
    if (get_mode()->get_opt_mode() != OP_MODE_STL){
        tx_offloads |= DEV_TX_OFFLOAD_VLAN_INSERT;
    }

    // disable non-supported best-effort offloads
    tx_offloads &= dev_info->tx_offload_capa;


    tx_offloads |= cfg.tx_offloads.common_required;

    if ( CGlobalInfo::m_options.preview.getTsoOffloadDisable() ) {
        tx_offloads &= ~(
            DEV_TX_OFFLOAD_TCP_TSO | 
            DEV_TX_OFFLOAD_UDP_TSO);
    }

    /* configure global rte_eth_conf  */
    check_offloads(dev_info, &eth_cfg);
    configure(rx_qs, tx_qs, &eth_cfg);

    /* configure tx que */
    for (uint16_t qid = 0; qid < tx_qs; qid++) {
        tx_queue_setup(qid, tx_descs , socket_id, 
                       &g_trex.m_port_cfg.m_tx_conf);
    }

    for (uint16_t qid = 0; qid < rx_qs; qid++) {
        if (isVerbose(0)) {
           printf(" rx_qid: %d (%d) \n", qid,rx_qs_descs[qid]);
        }
        rx_queue_setup(qid, rx_qs_descs[qid], 
                       socket_id, 
                       &cfg.m_rx_conf,
                       get_rx_mem_pool(socket_id));
    }
    if (rx_qs_drop_qid){
        set_rx_queue(MAIN_DPDK_RX_Q);
    }
}


COLD_FUNC void CPhyEthIF::conf_queues(void){
    CTrexDpdkParams dpdk_p;
    get_dpdk_drv_params(dpdk_p);

    uint16_t tx_qs;
    uint32_t tx_descs;
    uint16_t rx_qs;
    rx_que_desc_t rx_qs_descs;
    uint16_t rx_qs_drop_qid;
    trex_dpdk_rx_distro_mode_t rss_mode;
    bool in_astf_mode;
    bool is_drop_q = get_dpdk_mode()->is_drop_rx_queue_needed();

    in_astf_mode = get_mode()->is_astf_mode();
    rx_qs = dpdk_p.get_total_rx_queues();
    tx_descs = dpdk_p.tx_desc_num;
    rss_mode =get_dpdk_mode()->get_rx_distro_mode();

    if (get_dpdk_mode()->is_one_tx_rx_queue()) {
       tx_qs = 1;
       assert(rx_qs==1);
       rx_qs_descs.push_back(dpdk_p.rx_desc_num_data_q);
       rx_qs_drop_qid=0;
    }else{
       tx_qs = g_trex.m_max_queues_per_port;
       int i;
       for (i=0; i<rx_qs; i++) {
           uint16_t desc;
           if ( is_drop_q && 
               (i==MAIN_DPDK_DROP_Q) ){
               desc =dpdk_p.rx_desc_num_drop_q;
           }else{
               desc =dpdk_p.rx_desc_num_data_q;
           }
           rx_qs_descs.push_back(desc);
       }
       if (is_drop_q){
           rx_qs_drop_qid = MAIN_DPDK_RX_Q;
       }else{
           rx_qs_drop_qid = 0;
       }
    }

   _conf_queues(tx_qs,
                tx_descs,
                rx_qs,
                rx_qs_descs,
                rx_qs_drop_qid,
                rss_mode,
                in_astf_mode);

}

/**
 * get extended stats might fail on some drivers (i40e_vf) 
 * so wrap it another a watch 
 */
COLD_FUNC bool CPhyEthIF::get_extended_stats() {
    bool rc = get_ex_drv()->get_extended_stats(this, &m_stats);
    if (!rc) {
        m_stats_err_cnt++;
        assert(m_stats_err_cnt <= 5);
        return false;
    }
    
    /* clear the counter */
    m_stats_err_cnt = 0;
    return true;
}


COLD_FUNC void CPhyEthIF::update_counters() {
    bool rc = get_extended_stats();
    if (!rc) {
        return;
    }
    
    CRXCoreIgnoreStat ign_stats;

    g_trex.m_stx->get_ignore_stats(m_tvpid, ign_stats, true);
    
    m_stats.obytes -= ign_stats.get_tx_bytes();
    m_stats.opackets -= ign_stats.get_tx_pkts();
    m_ignore_stats.opackets += ign_stats.get_tx_pkts();
    m_ignore_stats.obytes += ign_stats.get_tx_bytes();
    m_ignore_stats.m_tx_arp += ign_stats.get_tx_arp();

    m_last_tx_rate      =  m_bw_tx.add(m_stats.obytes);
    m_last_rx_rate      =  m_bw_rx.add(m_stats.ibytes);
    m_last_tx_pps       =  m_pps_tx.add(m_stats.opackets);
    m_last_rx_pps       =  m_pps_rx.add(m_stats.ipackets);
}

COLD_FUNC bool CPhyEthIF::Create(tvpid_t  tvpid,
                       repid_t  repid) {
    m_tvpid      = tvpid;
    m_repid      = repid;

    m_last_rx_rate      = 0.0;
    m_last_tx_rate      = 0.0;
    m_last_tx_pps       = 0.0;

    m_port_attr    = g_trex.m_drv->create_port_attr(tvpid,repid);

    if ( !m_is_dummy ) {
        /* set src MAC addr */
        uint8_t empty_mac[ETHER_ADDR_LEN] = {0,0,0,0,0,0};
        if (! memcmp( CGlobalInfo::m_options.m_mac_addr[m_tvpid].u.m_mac.src, empty_mac, ETHER_ADDR_LEN)) {
            rte_eth_macaddr_get(m_repid,
                                (struct ether_addr *)&CGlobalInfo::m_options.m_mac_addr[m_tvpid].u.m_mac.src);
        }
    }

    return true;
}

const std::vector<std::pair<uint8_t, uint8_t>> &
CPhyEthIF::get_core_list() {

    /* lazy find */
    if (m_core_id_list.size() == 0) {

        for (uint8_t core_id = 0; core_id < g_trex.get_cores_tx(); core_id++) {

            /* iterate over all the directions*/
            for (uint8_t dir = 0 ; dir < CS_NUM; dir++) {
                if (g_trex.m_cores_vif[core_id + 1]->get_ports()[dir].m_port->get_tvpid() == m_tvpid) {
                    m_core_id_list.push_back(std::make_pair(core_id, dir));
                }
            }
        }
    }

    return m_core_id_list;

}

COLD_FUNC int CPhyEthIF::reset_hw_flow_stats() {
    if (get_ex_drv()->hw_rx_stat_supported()) {
        get_ex_drv()->reset_rx_stats(this, m_stats.m_fdir_prev_pkts, 0, MAX_FLOW_STATS);
    } else {
        get_stateless_obj()->get_stats()->reset_rx_stats(get_tvpid(), get_core_list());
    }
    return 0;
}

// get/reset flow director counters
// return 0 if OK. -1 if operation not supported.
// rx_stats, tx_stats - arrays of len max - min + 1. Returning rx, tx updated absolute values.
// min, max - minimum, maximum counters range to get
// reset - If true, need to reset counter value after reading
COLD_FUNC int CPhyEthIF::get_flow_stats(rx_per_flow_t *rx_stats, tx_per_flow_t *tx_stats, int min, int max, bool reset) {
    uint32_t diff_pkts[MAX_FLOW_STATS];
    uint32_t diff_bytes[MAX_FLOW_STATS];
    bool hw_rx_stat_supported = get_ex_drv()->hw_rx_stat_supported();

    if (hw_rx_stat_supported) {
        if (get_ex_drv()->get_rx_stats(this, diff_pkts, m_stats.m_fdir_prev_pkts
                                       , diff_bytes, m_stats.m_fdir_prev_bytes, min, max) < 0) {
            return -1;
        }
    } else {
        get_stateless_obj()->get_stats()->get_rx_stats(get_tvpid(), rx_stats, min, max, reset, TrexPlatformApi::IF_STAT_IPV4_ID, get_core_list());
    }

    for (int i = min; i <= max; i++) {
        if ( reset ) {
            // return value so far, and reset
            if (hw_rx_stat_supported) {
                if (rx_stats != NULL) {
                    rx_stats[i - min].set_pkts(m_stats.m_rx_per_flow_pkts[i] + diff_pkts[i]);
                    rx_stats[i - min].set_bytes(m_stats.m_rx_per_flow_bytes[i] + diff_bytes[i]);
                }
                m_stats.m_rx_per_flow_pkts[i] = 0;
                m_stats.m_rx_per_flow_bytes[i] = 0;
                get_ex_drv()->reset_rx_stats(this, &m_stats.m_fdir_prev_pkts[i], i, 1);

            }
            if (tx_stats != NULL) {
                tx_stats[i - min] = g_trex.clear_flow_tx_stats(m_tvpid, i, false);
            }
        } else {
            if (hw_rx_stat_supported) {
                m_stats.m_rx_per_flow_pkts[i] += diff_pkts[i];
                m_stats.m_rx_per_flow_bytes[i] += diff_bytes[i];
                if (rx_stats != NULL) {
                    rx_stats[i - min].set_pkts(m_stats.m_rx_per_flow_pkts[i]);
                    rx_stats[i - min].set_bytes(m_stats.m_rx_per_flow_bytes[i]);
                }
            }
            if (tx_stats != NULL) {
                tx_stats[i - min] = g_trex.get_flow_tx_stats(m_tvpid, i);
            }
        }
    }

    return 0;
}

COLD_FUNC int CPhyEthIF::get_flow_stats_payload(rx_per_flow_t *rx_stats, tx_per_flow_t *tx_stats, int min, int max, bool reset) {
    get_stateless_obj()->get_stats()->get_rx_stats(get_tvpid(), rx_stats, min, max, reset, TrexPlatformApi::IF_STAT_PAYLOAD, get_core_list());
    
    for (int i = min; i <= max; i++) {
        if ( reset ) {
            if (tx_stats != NULL) {
                tx_stats[i - min] = g_trex.clear_flow_tx_stats(m_tvpid, i + MAX_FLOW_STATS, true);
            }
        } else {
            if (tx_stats != NULL) {
                tx_stats[i - min] = g_trex.get_flow_tx_stats(m_tvpid, i + MAX_FLOW_STATS);
            }
        }
    }

    return 0;
}