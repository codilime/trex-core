#ifndef __TREX_PLATFORM_API_DPDK_H__
#define __TREX_PLATFORM_API_DPDK_H__

#include "trex_platform_api.h"

/**
 * DPDK implementation of the platform API
 *
 * @author imarom (26-Oct-15)
 */
class TrexDpdkPlatformApi : public TrexPlatformApi {
public:
    uint32_t  get_port_count() const;
    void      port_id_to_cores(uint8_t port_id, std::vector<std::pair<uint8_t, uint8_t>> &cores_id_list) const;
    void      global_stats_to_json(Json::Value &output) const;
    void      port_stats_to_json(Json::Value &output, uint8_t port_id) const;

    void get_port_info(uint8_t port_id, intf_info_st &info) const;

    void publish_async_data_now(uint32_t key, bool baseline) const;
    void publish_async_port_attr_changed(uint8_t port_id) const;
    uint8_t get_dp_core_count() const;
    
    void get_port_stat_info(uint8_t port_id, uint16_t &num_counters, uint16_t &capabilities
                                 , uint16_t &ip_id_base) const;
    int get_flow_stats(uint8_t port_id, void *stats, void *tx_stats, int min, int max, bool reset
                       , TrexPlatformApi::driver_stat_cap_e type) const;
    int get_rfc2544_info(void *rfc2544_info, int min, int max, bool reset, bool period_switch) const;
    int get_rx_err_cntrs(void *rx_err_cntrs) const;
    int reset_hw_flow_stats(uint8_t port_id) const;
    bool hw_rx_stat_supported() const;
    virtual int add_rx_flow_stat_rule(uint8_t port_id, uint16_t l3_type, uint8_t l4_proto
                                      , uint8_t ipv6_next_h, uint16_t id) const;
    virtual int del_rx_flow_stat_rule(uint8_t port_id, uint16_t l3_type, uint8_t l4_proto
                                      , uint8_t ipv6_next_h, uint16_t id) const;
    int get_active_pgids(flow_stat_active_t_new &result) const;
    int get_cpu_util_full(cpu_util_full_t &result) const;
    int get_mbuf_util(Json::Value &result) const;
    int get_pgid_stats(Json::Value &json, std::vector<uint32_t> pgids) const;
    void mark_for_shutdown() const;
    CFlowStatParser *get_flow_stat_parser() const;
    TRexPortAttr *getPortAttrObj(uint8_t port_id) const;

    int get_xstats_values(uint8_t port_id, xstats_values_t &xstats_values) const;
    int get_xstats_names(uint8_t port_id, xstats_names_t &xstats_names) const;

    CSyncBarrier * get_sync_barrier(void) const;
    CFlowGenList * get_fl() const;
};

#endif /* __TREX_PLATFORM_API_DPDK_H__ */