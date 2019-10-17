/*
Copyright (c) 2015-2015 Cisco Systems, Inc.

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

#include "trex_port_attr.h"
#include "bp_sim.h"
#include "trex_global_object.h"
#include "hot_section.h"


std::string TRexPortAttr::get_rx_filter_mode() const {
    switch (m_rx_filter_mode) {
    case RX_FILTER_MODE_ALL:
        return "all";
    case RX_FILTER_MODE_HW:
        return "hw";
    default:
        assert(0);
    }
}

void TRexPortAttr::to_json(Json::Value &output) {

    output["promiscuous"]["enabled"] = get_promiscuous();
    output["multicast"]["enabled"]   = get_multicast();
    output["link"]["up"]             = is_link_up();
    output["speed"]                  = get_link_speed() / 1000.0;
    output["rx_filter_mode"]         = get_rx_filter_mode();

    Json::Value vxlan_fs_ports = Json::arrayValue;
    for (auto vxlan_fs_port : m_vxlan_fs_ports) {
        vxlan_fs_ports.append(vxlan_fs_port);
    }
    output["vxlan_fs"]               = vxlan_fs_ports;

    int mode;
    get_flow_ctrl(mode);
    output["fc"]["mode"] = mode;
}

COLD_FUNC int DpdkTRexPortAttr::add_mac(char * mac){
    struct ether_addr mac_addr;
    for (int i=0; i<6;i++) {
        mac_addr.addr_bytes[i] =mac[i];
    }

    if ( get_ex_drv()->hardware_support_mac_change() ) {
        if ( rte_eth_dev_mac_addr_add(m_repid, &mac_addr,0) != 0) {
            printf("Failed setting MAC for port %d \n", (int)m_repid);
            exit(-1);
        }
    }

    return 0;
}

int DpdkTRexPortAttrMlnx5G::set_link_up(bool up) {
    TrexMonitor * cur_monitor = TrexWatchDog::getInstance().get_current_monitor();
    if (cur_monitor != NULL) {
        cur_monitor->disable(5); // should take ~2.5 seconds
    }
    int result = DpdkTRexPortAttr::set_link_up(up);
    if (cur_monitor != NULL) {
        cur_monitor->enable();
    }
    return result;
}

COLD_FUNC bool DpdkTRexPortAttr::update_link_status_nowait(){
    rte_eth_link new_link;
    bool changed = false;
    rte_eth_link_get_nowait(m_repid, &new_link);

    if (new_link.link_speed != m_link.link_speed ||
                new_link.link_duplex != m_link.link_duplex ||
                    new_link.link_autoneg != m_link.link_autoneg ||
                        new_link.link_status != m_link.link_status) {
        changed = true;

        /* in case of link status change - notify the dest object */
        if (new_link.link_status != m_link.link_status && get_is_interactive()) {
            if ( g_trex.m_stx != nullptr ) {
                g_trex.m_stx->get_port_by_id(m_port_id)->invalidate_dst_mac();
            }
        }
    }

    m_link = new_link;
    return changed;
}

int DpdkTRexPortAttr::set_rx_filter_mode(rx_filter_mode_e rx_filter_mode) {

    if (rx_filter_mode == m_rx_filter_mode) {
        return (0);
    }

    CPhyEthIF *_if = g_trex.m_ports[m_tvpid];
    bool recv_all = (rx_filter_mode == RX_FILTER_MODE_ALL);
    int rc = _if->set_port_rcv_all(recv_all);
    if (rc != 0) {
        return (rc);
    }

    m_rx_filter_mode = rx_filter_mode;

    return (0);
}

bool DpdkTRexPortAttr::is_loopback() const {
    uint8_t port_id;
    return g_trex.lookup_port_by_mac(CGlobalInfo::m_options.get_dst_src_mac_addr(m_port_id), port_id);
}
