#include "trex_platform_api_dpdk.h"
#include "trex_global_object.h"

/***********************************************************
 * platfrom API object
 **********************************************************/
int TrexDpdkPlatformApi::get_xstats_values(uint8_t port_id, xstats_values_t &xstats_values) const {
    return g_trex.m_ports[port_id]->get_port_attr()->get_xstats_values(xstats_values);
}

int TrexDpdkPlatformApi::get_xstats_names(uint8_t port_id, xstats_names_t &xstats_names) const {
    return g_trex.m_ports[port_id]->get_port_attr()->get_xstats_names(xstats_names);
}

void TrexDpdkPlatformApi::global_stats_to_json(Json::Value &output) const {
    g_trex.global_stats_to_json(output);
}

void TrexDpdkPlatformApi::port_stats_to_json(Json::Value &output, uint8_t port_id) const {
    g_trex.port_stats_to_json(output, port_id);
}

uint32_t TrexDpdkPlatformApi::get_port_count() const {
    return g_trex.m_max_ports;
}

uint8_t TrexDpdkPlatformApi::get_dp_core_count() const {
    return CGlobalInfo::m_options.get_number_of_dp_cores_needed();
}

void TrexDpdkPlatformApi::port_id_to_cores(uint8_t port_id, std::vector<std::pair<uint8_t, uint8_t>> &cores_id_list) const {
    CPhyEthIF *lpt = g_trex.m_ports[port_id];

    /* copy data from the interface */
    cores_id_list = lpt->get_core_list();
}

void TrexDpdkPlatformApi::get_port_info(uint8_t port_id, intf_info_st &info) const {
    struct ether_addr rte_mac_addr = {{0}};

    if ( g_trex.m_ports[port_id]->is_dummy() ) {
        info.driver_name = "Dummy";
    } else {
        info.driver_name = CTRexExtendedDriverDb::Ins()->get_driver_name();
    }

    /* mac INFO */

    /* hardware */
    g_trex.m_ports[port_id]->get_port_attr()->get_hw_src_mac(&rte_mac_addr);
    assert(ETHER_ADDR_LEN == 6);

    memcpy(info.hw_macaddr, rte_mac_addr.addr_bytes, 6);

    info.numa_node = g_trex.m_ports[port_id]->get_port_attr()->get_numa();
    info.pci_addr = g_trex.m_ports[port_id]->get_port_attr()->get_pci_addr();
}

void TrexDpdkPlatformApi::publish_async_data_now(uint32_t key,
                                                          bool baseline) const {
  g_trex.publish_async_data(true, baseline);
  g_trex.publish_async_barrier(key);
}

void TrexDpdkPlatformApi::publish_async_port_attr_changed(uint8_t port_id) const {
    g_trex.publish_async_port_attr_changed(port_id);
}

void TrexDpdkPlatformApi::get_port_stat_info(uint8_t port_id, uint16_t &num_counters, uint16_t &capabilities
                                             , uint16_t &ip_id_base) const {
    get_ex_drv()->get_rx_stat_capabilities(capabilities, num_counters ,ip_id_base);
}

int TrexDpdkPlatformApi::get_flow_stats(uint8_t port_id, void *rx_stats, void *tx_stats, int min, int max, bool reset
                                        , TrexPlatformApi::driver_stat_cap_e type) const {
    if (g_trex.is_marked_for_shutdown()) {
        return 0;
    }
    if (type == TrexPlatformApi::IF_STAT_PAYLOAD) {
        return g_trex.m_ports[port_id]->get_flow_stats_payload((rx_per_flow_t *)rx_stats, (tx_per_flow_t *)tx_stats
                                                              , min, max, reset);
    } else {
        return g_trex.m_ports[port_id]->get_flow_stats((rx_per_flow_t *)rx_stats, (tx_per_flow_t *)tx_stats
                                                      , min, max, reset);
    }
}

int TrexDpdkPlatformApi::get_rfc2544_info(void *rfc2544_info, int min, int max, bool reset
                                          , bool period_switch) const {
    return get_stateless_obj()->get_stats()->get_rfc2544_info((rfc2544_info_t *)rfc2544_info, min, max, reset, period_switch);
}

int TrexDpdkPlatformApi::get_rx_err_cntrs(void *rx_err_cntrs) const {
    return get_stateless_obj()->get_stats()->get_rx_err_cntrs((CRxCoreErrCntrs *)rx_err_cntrs);
}

int TrexDpdkPlatformApi::reset_hw_flow_stats(uint8_t port_id) const {
    return g_trex.m_ports[port_id]->reset_hw_flow_stats();
}

bool TrexDpdkPlatformApi::hw_rx_stat_supported() const {
    return get_ex_drv()->hw_rx_stat_supported();
}

int TrexDpdkPlatformApi::add_rx_flow_stat_rule(uint8_t port_id, uint16_t l3_type, uint8_t l4_proto
                                               , uint8_t ipv6_next_h, uint16_t id) const {
    if (!get_dpdk_mode()->is_hardware_filter_needed()) {
        return 0;
    }
    CPhyEthIF * lp=g_trex.m_ports[port_id];

    return get_ex_drv()->add_del_rx_flow_stat_rule(lp, RTE_ETH_FILTER_ADD, l3_type, l4_proto, ipv6_next_h, id);
}

int TrexDpdkPlatformApi::del_rx_flow_stat_rule(uint8_t port_id, uint16_t l3_type, uint8_t l4_proto
                                               , uint8_t ipv6_next_h, uint16_t id) const {
    if (!get_dpdk_mode()->is_hardware_filter_needed()) {
        return 0;
    }

    CPhyEthIF * lp=g_trex.m_ports[port_id];


    return get_ex_drv()->add_del_rx_flow_stat_rule(lp, RTE_ETH_FILTER_DELETE, l3_type, l4_proto, ipv6_next_h, id);
}

int TrexDpdkPlatformApi::get_active_pgids(flow_stat_active_t_new &result) const {
    return CFlowStatRuleMgr::instance()->get_active_pgids(result);
}

int TrexDpdkPlatformApi::get_cpu_util_full(cpu_util_full_t &cpu_util_full) const {
    uint8_t p1;
    uint8_t p2;

    cpu_util_full.resize((int)g_trex.m_fl.m_threads_info.size());
    for (int thread_id=0; thread_id<(int)g_trex.m_fl.m_threads_info.size(); thread_id++) {

        /* history */
        CFlowGenListPerThread *lp = g_trex.m_fl.m_threads_info[thread_id];
        cpu_vct_st &per_cpu = cpu_util_full[thread_id];
        lp->m_cpu_cp_u.GetHistory(per_cpu);


        /* active ports */
        lp->get_port_ids(p1, p2);
        per_cpu.m_port1 = (lp->is_port_active(p1) ? p1 : -1);
        per_cpu.m_port2 = (lp->is_port_active(p2) ? p2 : -1);

    }
    return 0;
}

int TrexDpdkPlatformApi::get_mbuf_util(Json::Value &mbuf_pool) const {
    CGlobalInfo::dump_pool_as_json(mbuf_pool);
    return 0;
}

int TrexDpdkPlatformApi::get_pgid_stats(Json::Value &json, std::vector<uint32_t> pgids) const {
    g_trex.sync_threads_stats();
    CFlowStatRuleMgr::instance()->dump_json(json, pgids);
    return 0;
}

CFlowStatParser* TrexDpdkPlatformApi::get_flow_stat_parser() const {
    return get_ex_drv()->get_flow_stat_parser();
}

TRexPortAttr* TrexDpdkPlatformApi::getPortAttrObj(uint8_t port_id) const {
    return g_trex.m_ports[port_id]->get_port_attr();
}

void TrexDpdkPlatformApi::mark_for_shutdown() const {
    g_trex.mark_for_shutdown(CGlobalTRex::SHUTDOWN_RPC_REQ);
}

CSyncBarrier* TrexDpdkPlatformApi::get_sync_barrier(void) const {
    return g_trex.m_sync_barrier;
}

CFlowGenList* TrexDpdkPlatformApi::get_fl() const {
    return &g_trex.m_fl;
}