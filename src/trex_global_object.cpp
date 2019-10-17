#include "trex_global_object.h"
#include "interface/phy_eth_if_dummy.h"

CGlobalTRex g_trex;

// Before starting, send gratuitous ARP on our addresses, and try to resolve dst MAC addresses.
COLD_FUNC void CGlobalTRex::pre_test() {
    CTrexDpdkParams dpdk_p;
    get_dpdk_drv_params(dpdk_p);
    CPretest pretest(m_max_ports, dpdk_p.get_total_rx_queues());

    int i;
    for (i=0; i<m_max_ports; i++) {
        pretest.set_port(i, m_ports[i]);
    }
    bool resolve_needed = false;
    uint8_t empty_mac[ETHER_ADDR_LEN] = {0,0,0,0,0,0};
    bool need_grat_arp[TREX_MAX_PORTS];

    if (CGlobalInfo::m_options.preview.get_is_client_cfg_enable()) {
        std::vector<ClientCfgCompactEntry *> conf;
        m_fl.get_client_cfg_ip_list(conf);

        // If we got src MAC for port in global config, take it, otherwise use src MAC from DPDK
        uint8_t port_macs[m_max_ports][ETHER_ADDR_LEN];
        for (int port_id = 0; port_id < m_max_ports; port_id++) {
            memcpy(port_macs[port_id], CGlobalInfo::m_options.m_mac_addr[port_id].u.m_mac.src, ETHER_ADDR_LEN);
        }

        for (std::vector<ClientCfgCompactEntry *>::iterator it = conf.begin(); it != conf.end(); it++) {
            uint8_t port = (*it)->get_port();
            uint16_t vlan = (*it)->get_vlan();
            uint32_t count = (*it)->get_count();
            uint32_t dst_ip = (*it)->get_dst_ip();
            uint32_t src_ip = (*it)->get_src_ip();

            for (int i = 0; i < count; i++) {
                //??? handle ipv6;
                if ((*it)->is_ipv4()) {
                    pretest.add_next_hop(port, dst_ip + i, vlan);
                }
            }
            if (!src_ip) {
                src_ip = CGlobalInfo::m_options.m_ip_cfg[port].get_ip();
                if (!src_ip) {
                    fprintf(stderr, "No matching src ip for port: %d ip:%s vlan: %d\n"
                            , port, ip_to_str(dst_ip).c_str(), vlan);
                    fprintf(stderr, "You must specify src_ip in client config file or in TRex config file\n");
                    exit(1);
                }
            }
            pretest.add_ip(port, src_ip, vlan, port_macs[port]);
            COneIPv4Info ipv4(src_ip, vlan, port_macs[port], port);
            m_mg.add_grat_arp_src(ipv4);

            delete *it;
        }
        if ( isVerbose(1)) {
            fprintf(stdout, "*******Pretest for client cfg********\n");
            pretest.dump(stdout);
            }
    } else {
        for (int port_id = 0; port_id < m_max_ports; port_id++) {
            if ( m_ports[port_id]->is_dummy() ) {
                continue;
            }
            if (! memcmp( CGlobalInfo::m_options.m_mac_addr[port_id].u.m_mac.dest, empty_mac, ETHER_ADDR_LEN)) {
                resolve_needed = true;
            } else {
                resolve_needed = false;
            }

            if ( !m_ports[port_id]->get_port_attr()->is_link_up() && get_is_interactive() ) {
                resolve_needed = false;
            }

            need_grat_arp[port_id] = CGlobalInfo::m_options.m_ip_cfg[port_id].get_ip() != 0;

            pretest.add_ip(port_id, CGlobalInfo::m_options.m_ip_cfg[port_id].get_ip()
                           , CGlobalInfo::m_options.m_ip_cfg[port_id].get_vlan()
                           , CGlobalInfo::m_options.m_mac_addr[port_id].u.m_mac.src);

            if (resolve_needed) {
                pretest.add_next_hop(port_id, CGlobalInfo::m_options.m_ip_cfg[port_id].get_def_gw()
                                     , CGlobalInfo::m_options.m_ip_cfg[port_id].get_vlan());
            }
        }
    }

    for (int port_id = 0; port_id < m_max_ports; port_id++) {
        CPhyEthIF *pif = m_ports[port_id];
        // Configure port to send all packets to software
        pif->set_port_rcv_all(true);
    }

    pretest.send_grat_arp_all();
    bool ret;
    int count = 0;
    bool resolve_failed = false;
    do {
        ret = pretest.resolve_all();
        count++;
    } while ((ret != true) && (count < 10));
    if (ret != true) {
        resolve_failed = true;
    }

    if ( isVerbose(1) ) {
        fprintf(stdout, "*******Pretest after resolving ********\n");
        pretest.dump(stdout);
    }

    if (CGlobalInfo::m_options.preview.get_is_client_cfg_enable()) {
        CManyIPInfo pretest_result;
        pretest.get_results(pretest_result);
        if (resolve_failed) {
            fprintf(stderr, "Resolution of following IPs failed. Exiting.\n");
            for (const COneIPInfo *ip=pretest_result.get_next(); ip != NULL;
                   ip = pretest_result.get_next()) {
                if (ip->resolve_needed()) {
                    ip->dump(stderr, "  ");
                }
            }
            exit(1);
        }
        m_fl.set_client_config_resolved_macs(&pretest_result);
        if ( isVerbose(1) ) {
            m_fl.dump_client_config(stdout);
        }

        bool port_found[TREX_MAX_PORTS];
        for (int port_id = 0; port_id < m_max_ports; port_id++) {
            port_found[port_id] = false;
        }
        // If client config enabled, we don't resolve MACs from trex_cfg.yaml. For latency (-l)
        // We need to able to send packets from RX core, so need to configure MAC/vlan for each port.
        for (const COneIPInfo *ip=pretest_result.get_next(); ip != NULL; ip = pretest_result.get_next()) {
            // Use first MAC/vlan we see on each port
            uint8_t port_id = ip->get_port();
            uint16_t vlan = ip->get_vlan();
            if ( ! port_found[port_id]) {
                port_found[port_id] = true;
                ip->get_mac(CGlobalInfo::m_options.m_mac_addr[port_id].u.m_mac.dest);
                CGlobalInfo::m_options.m_ip_cfg[port_id].set_vlan(vlan);
            }
        }
    } else {
        uint8_t mac[ETHER_ADDR_LEN];
        for (int port_id = 0; port_id < m_max_ports; port_id++) {
            if ( m_ports[port_id]->is_dummy() ) {
                continue;
            }
            if (! memcmp(CGlobalInfo::m_options.m_mac_addr[port_id].u.m_mac.dest, empty_mac, ETHER_ADDR_LEN)) {
                // we don't have dest MAC. Get it from what we resolved.
                uint32_t ip = CGlobalInfo::m_options.m_ip_cfg[port_id].get_def_gw();
                uint16_t vlan = CGlobalInfo::m_options.m_ip_cfg[port_id].get_vlan();

                if (!pretest.get_mac(port_id, ip, vlan, mac)) {
                    fprintf(stderr, "Failed resolving dest MAC for default gateway:%d.%d.%d.%d on port %d\n"
                            , (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF, port_id);

                    if (get_is_interactive()) {
                        continue;
                    } else {
                        exit(1);
                    }
                }

                memcpy(CGlobalInfo::m_options.m_mac_addr[port_id].u.m_mac.dest, mac, ETHER_ADDR_LEN);
                // if port is connected in loopback, no need to send gratuitous ARP. It will only confuse our ingress counters.
                if (need_grat_arp[port_id] && (! pretest.is_loopback(port_id))) {
                    COneIPv4Info ipv4(CGlobalInfo::m_options.m_ip_cfg[port_id].get_ip()
                                      , CGlobalInfo::m_options.m_ip_cfg[port_id].get_vlan()
                                      , CGlobalInfo::m_options.m_mac_addr[port_id].u.m_mac.src
                                      , port_id);
                    m_mg.add_grat_arp_src(ipv4);
                }
            }
        }
    }

    // some adapters (napatech at least) have a little delayed statistics
    if (get_ex_drv()->sleep_after_arp_needed() ){
        sleep(1);
    }

    // update statistics baseline, so we can ignore what happened in pre test phase
    for (int port_id = 0; port_id < m_max_ports; port_id++) {
        CPhyEthIF *pif = m_ports[port_id];
        if ( !pif->is_dummy() ) {
            CPreTestStats pre_stats = pretest.get_stats(port_id);
            pif->set_ignore_stats_base(pre_stats);
            // Configure port back to normal mode. Only relevant packets handled by software.
            pif->set_port_rcv_all(false);
        }
    }
}

COLD_FUNC void CGlobalTRex::run_bird_with_ns() {
    if ( CGlobalInfo::m_options.m_is_bird_enabled ) {
        auto &ports_map = m_stx->get_port_map();
        assert(!ports_map.empty());
        TrexPort *first_port = ports_map.begin()->second;
        
        if ( !(first_port->get_stack_caps() & CStackBase::BIRD) ) {
            std::string stack_name = CGlobalInfo::m_options.m_stack_type;
            rte_exit(EXIT_FAILURE, "Cannot run Bird on %s stack mode \n", stack_name.c_str());
        }
    }
}

COLD_FUNC void CGlobalTRex::apply_pretest_results_to_stack(void) {
    // wait up to 5 seconds for RX core to be up
    for (int i=0; i<50; i++) {
        if ( m_stx->get_rx()->is_active() ) {
            break;
        }
        delay(100);
    }

    assert(m_stx->get_rx()->is_active());

    for (int port_id = 0; port_id < m_max_ports; port_id++) {
        if ( m_ports[port_id]->is_dummy() ) {
            continue;
        }
        TrexPort *port = m_stx->get_port_by_id(port_id);
        uint32_t src_ipv4 = CGlobalInfo::m_options.m_ip_cfg[port_id].get_ip();
        uint32_t dg = CGlobalInfo::m_options.m_ip_cfg[port_id].get_def_gw();
        std::string dst_mac((char*)CGlobalInfo::m_options.m_mac_addr[port_id].u.m_mac.dest, 6);

        /* L3 mode */
        if (src_ipv4 && dg) {
            if ( dst_mac == std::string("\0\0\0\0\0\0", 6) ) {
                port->set_l3_mode_async(utl_uint32_to_ipv4_buf(src_ipv4), utl_uint32_to_ipv4_buf(dg), nullptr);
            } else {
                port->set_l3_mode_async(utl_uint32_to_ipv4_buf(src_ipv4), utl_uint32_to_ipv4_buf(dg), &dst_mac);
            }

        /* L2 mode */
        } else if (CGlobalInfo::m_options.m_mac_addr[port_id].u.m_mac.is_set) {
            port->set_l2_mode_async(dst_mac);
        }

        /* configure single VLAN */
        uint16_t vlan = CGlobalInfo::m_options.m_ip_cfg[port_id].get_vlan();
        if (vlan != 0) {
            port->set_vlan_cfg_async({vlan});
        }
        port->run_rx_cfg_tasks_initial_async();
    }

    bool success = true;
    for (int port_id = 0; port_id < m_max_ports; port_id++) {
        if ( m_ports[port_id]->is_dummy() ) {
            continue;
        }
        TrexPort *port = m_stx->get_port_by_id(port_id);
        while ( port->is_rx_running_cfg_tasks() ) {
            rte_pause_or_delay_lowend();
        }
        stack_result_t results;
        port->get_rx_cfg_tasks_results(0, results);
        if ( results.err_per_mac.size() ) {
            success = false;
            printf("Configure port node %d failed with following error:\n", port_id);
            printf("%s\n", results.err_per_mac.begin()->second.c_str());
        }
    }
    if ( !success ) {
        exit(1);
    }
}

/**
 * handle an abort
 *
 * when in stateless mode this routine will try to safely
 * publish over ZMQ the assert cause
 *
 * *BEWARE* - this function should be thread safe
 *            as any thread can call assert
 */
COLD_FUNC void CGlobalTRex::abort_gracefully(const std::string &on_stdout,
                              const std::string &on_publisher) {

    /* first to stdout */
    std::cout << on_stdout << "\n";

    /* assert might be before the ZMQ publisher was connected */
    if (m_zmq_publisher.is_connected()) {

        /* generate the data */
        Json::Value data;
        data["cause"] = on_publisher;

        /* if this is the control plane thread - acquire the lock again (recursive), if it is dataplane - hold up */
        std::unique_lock<std::recursive_mutex> cp_lock(m_cp_lock);
        m_zmq_publisher.publish_event(TrexPublisher::EVENT_SERVER_STOPPED, data);

        /* close the publisher gracefully to ensure message was delivered */
        m_zmq_publisher.Delete(2);
    }


    /* so long... */
    abort();
}


COLD_FUNC bool CGlobalTRex::is_all_links_are_up(bool dump){
    bool all_link_are=true;
    int i;
    for (i=0; i<m_max_ports; i++) {
        CPhyEthIF * _if=m_ports[i];
        _if->get_port_attr()->update_link_status();
        if ( dump ){
            _if->dump_stats(stdout);
        }
        if ( _if->get_port_attr()->is_link_up() == false){
            all_link_are=false;
            break;
        }
    }
    return (all_link_are);
}

COLD_FUNC void CGlobalTRex::wait_for_all_cores(){

    // no need to delete rx_msg. Deleted by receiver
    bool all_core_finished = false;
    int i;
    for (i=0; i<20; i++) {
        if ( is_all_cores_finished() ){
            all_core_finished =true;
            break;
        }
        delay(100);
    }

    Json::Value data;
    data["cause"] = get_shutdown_cause();
    m_zmq_publisher.publish_event(TrexPublisher::EVENT_SERVER_STOPPED, data);

    if ( all_core_finished ){
        printf(" All cores stopped !! \n");
    }else{
        if ( !m_stx->get_rx()->is_active() ) {
            printf(" ERROR RX core is stuck!\n");
        } else {
            printf(" ERROR one of the DP cores is stuck!\n");
        }
    }
}


COLD_FUNC int  CGlobalTRex::device_rx_queue_flush(){
    int i;
    for (i=0; i<m_max_ports; i++) {
        CPhyEthIF * _if=m_ports[i];
        _if->flush_rx_queue();
    }
    return (0);
}


// init RX core for batch mode (STF, ASTF batch)
COLD_FUNC void CGlobalTRex::rx_batch_conf(void) {
    int i;
    CLatencyManagerCfg mg_cfg;
    mg_cfg.m_max_ports = m_max_ports;

    uint32_t latency_rate=CGlobalInfo::m_options.m_latency_rate;

    if ( latency_rate ) {
        mg_cfg.m_cps = (double)latency_rate ;
    } else {
        // If RX core needed, we need something to make the scheduler running.
        // If nothing configured, send 1 CPS latency measurement packets.
        if (CGlobalInfo::m_options.m_arp_ref_per == 0) {
            mg_cfg.m_cps = 1.0;
        } else {
            mg_cfg.m_cps = 0;
        }
    }

    if ( !get_dpdk_mode()->is_hardware_filter_needed() ) {
        /* vm mode, indirect queues  */
        for (i=0; i<m_max_ports; i++) {
            CPhyEthIF * _if = m_ports[i];
            CMessagingManager * rx_dp=CMsgIns::Ins()->getRxDp();

            uint8_t thread_id = (i>>1);

            CNodeRing * r = rx_dp->getRingCpToDp(thread_id);
            bool disable_rx_read = !get_dpdk_mode()->is_rx_core_read_from_queue();
            m_latency_vm_vports[i].Create((uint8_t)i, r, &m_mg, _if, disable_rx_read);
            mg_cfg.m_ports[i] = &m_latency_vm_vports[i];
        }

    } else {
        for (i=0; i<m_max_ports; i++) {
            CPhyEthIF * _if=m_ports[i];
            //_if->dump_stats(stdout);
            m_latency_vports[i].Create(_if, m_rx_core_tx_q_id, 1);

            mg_cfg.m_ports[i] = &m_latency_vports[i];
        }
    }

    m_mg.Create(&mg_cfg);
    m_mg.set_mask(CGlobalInfo::m_options.m_latency_mask);
}


COLD_FUNC void CGlobalTRex::rx_interactive_conf(void) {
    
    if ( !get_dpdk_mode()->is_hardware_filter_needed() ) {
        /* vm mode, indirect queues  */
        for (int i=0; i < m_max_ports; i++) {
            CPhyEthIF * _if = m_ports[i];
            CMessagingManager * rx_dp = CMsgIns::Ins()->getRxDp();
            uint8_t thread_id = (i >> 1);
            CNodeRing * r = rx_dp->getRingCpToDp(thread_id);
            bool disable_rx_read = (!get_dpdk_mode()->is_rx_core_read_from_queue());
            m_latency_vm_vports[i].Create(i, r, &m_mg, _if, disable_rx_read);
        }
    } else {
        for (int i = 0; i < m_max_ports; i++) {
            CPhyEthIF * _if = m_ports[i];
            m_latency_vports[i].Create(_if, m_rx_core_tx_q_id, 1);
        }
    }
}


COLD_FUNC int  CGlobalTRex::device_start(void){
    int i;
    for (i=0; i<m_max_ports; i++) {
        socket_id_t socket_id = CGlobalInfo::m_socket.port_to_socket((port_id_t)i);
        assert(CGlobalInfo::m_mem_pool[socket_id].m_mbuf_pool_2048);
        CTVPort ctvport = CTVPort(i);
        if ( ctvport.is_dummy() ) {
            m_ports[i] = new CPhyEthIFDummy();
        } else {
            m_ports[i] = new CPhyEthIF();
        }
        CPhyEthIF * _if=m_ports[i];
        _if->Create((uint8_t)i, ctvport.get_repid());
        _if->conf_queues();
        _if->stats_clear();
        _if->start();
        _if->configure_rss();
        if (CGlobalInfo::m_options.preview.getPromMode()) {
            _if->get_port_attr()->set_promiscuous(true);
            _if->get_port_attr()->set_multicast(true);
        }

        _if->configure_rx_duplicate_rules();

        if ( ! CGlobalInfo::m_options.preview.get_is_disable_flow_control_setting()
             && _if->get_port_attr()->is_fc_change_supported()) {
            _if->disable_flow_control();
        }

        _if->get_port_attr()->add_mac((char *)CGlobalInfo::m_options.get_src_mac_addr(i));

        fflush(stdout);
    }

    if ( !is_all_links_are_up()  ){
        /* wait for ports to be stable */
        get_ex_drv()->wait_for_stable_link();

        if ( !is_all_links_are_up() ){ // disable start with link down for now

            if ( get_is_interactive() ) {
                printf(" WARNING : there is no link on one of the ports, interactive mode can continue\n");
            } else if ( get_ex_drv()->drop_packets_incase_of_linkdown() ) {
                printf(" WARNING : there is no link on one of the ports, driver support auto drop in case of link down - continue\n");
            } else {
                dump_links_status(stdout);
                rte_exit(EXIT_FAILURE, " One of the links is down \n");
            }
        }
    } else {
        get_ex_drv()->wait_after_link_up();
    }

    dump_links_status(stdout);

    device_rx_queue_flush();

    return (0);
}


COLD_FUNC void
CGlobalTRex::init_vif_cores() {
    int port_offset = 0;
    uint8_t lat_q_id;

    if (get_dpdk_mode()->is_dp_latency_tx_queue()) {
        lat_q_id = get_latency_tx_queue_id();
    } else {
        lat_q_id = 0;
    }
    for (int i = 0; i < get_cores_tx(); i++) {
        int j=(i+1);
        int queue_id=((j-1)/get_base_num_cores() );   /* for the first min core queue 0 , then queue 1 etc */
     
        m_cores_vif[j]->Create(j,
                               queue_id,
                               m_ports[port_offset], /* 0,2*/
                               queue_id,
                               m_ports[port_offset+1], /*1,3*/
                               lat_q_id);
        port_offset+=2;
        if (port_offset == m_max_ports) {
            port_offset = 0;
            // We want to allow sending latency packets only from first core handling a port
            lat_q_id = CCoreEthIF::INVALID_Q_ID;
        }
    }

    m_rx_core_tx_q_id = get_rx_core_tx_queue_id();
    fprintf(stdout," -------------------------------\n");
    fprintf(stdout, "RX core uses TX queue number %d on all ports\n", (int)m_rx_core_tx_q_id);
    CCoreEthIF::DumpIfCfgHeader(stdout);
    for (int i = 0; i < get_cores_tx(); i++) {
        m_cores_vif[i+1]->DumpIfCfg(stdout);
    }
    fprintf(stdout," -------------------------------\n");
}


static void trex_termination_handler(int signum);


COLD_FUNC bool CGlobalTRex::Create(){

    register_signals();

    m_stats_cnt =0;
    
    /* End update pre flags */

    device_prob_init();
    cores_prob_init();
    queues_prob_init();


    if ( !m_zmq_publisher.Create( CGlobalInfo::m_options.m_zmq_port,
                                  !CGlobalInfo::m_options.preview.get_zmq_publish_enable() ) ){
        return (false);
    }


    /* allocate rings */
    assert( CMsgIns::Ins()->Create(get_cores_tx()) );

    if ( sizeof(CGenNodeNatInfo) != sizeof(CGenNode)  ) {
        printf("ERROR sizeof(CGenNodeNatInfo) %lu != sizeof(CGenNode) %lu must be the same size \n",sizeof(CGenNodeNatInfo),sizeof(CGenNode));
        assert(0);
    }

    if ( sizeof(CGenNodeLatencyPktInfo) != sizeof(CGenNode)  ) {
        printf("ERROR sizeof(CGenNodeLatencyPktInfo) %lu != sizeof(CGenNode) %lu must be the same size \n",sizeof(CGenNodeLatencyPktInfo),sizeof(CGenNode));
        assert(0);
    }

    /* allocate the memory */
    CTrexDpdkParams dpdk_p;
    get_dpdk_drv_params(dpdk_p);

    if (isVerbose(0)) {
        dpdk_p.dump(stdout);
    }

    bool use_hugepages = !CGlobalInfo::m_options.m_is_vdev;
    CGlobalInfo::init_pools( m_max_ports * dpdk_p.get_total_rx_desc(),
                             dpdk_p.rx_mbuf_type,
                             use_hugepages);

    device_start();
    dump_config(stdout);
    m_sync_barrier =new CSyncBarrier(get_cores_tx(),1.0);


    switch (get_op_mode()) {

    case OP_MODE_STL:
        init_stl();
        break;

    case OP_MODE_ASTF:
        init_astf();
        break;

    case OP_MODE_STF:
        init_stf();
        break;

    case OP_MODE_ASTF_BATCH:
        init_astf_batch();
        break;

    default:
        assert(0);
    }

    
    return (true);

}

COLD_FUNC TrexSTXCfg
 CGlobalTRex::get_stx_cfg() {

    TrexSTXCfg cfg;
    
    /* control plane config */
    cfg.m_rpc_req_resp_cfg.create(TrexRpcServerConfig::RPC_PROT_TCP,
                                  global_platform_cfg_info.m_zmq_rpc_port,
                                  &m_cp_lock,
                                  CGlobalInfo::m_options.rpc_logfile_name);
    
    bool hw_filter = (get_dpdk_mode()->is_hardware_filter_needed());
    std::unordered_map<uint8_t, CPortLatencyHWBase*> ports;
    
    for (int i = 0; i < m_max_ports; i++) {
        if ( CTVPort(i).is_dummy() ) {
            continue;
        }
        if (!hw_filter) {
            ports[i] = &m_latency_vm_vports[i];
        } else {
            ports[i] = &m_latency_vports[i];
        }
    }
    
    /* RX core */
    cfg.m_rx_cfg.create(get_cores_tx(),
                        ports);
    
    cfg.m_publisher = &m_zmq_publisher;
    
    return cfg;
}


COLD_FUNC void CGlobalTRex::init_stl() {
    
    for (int i = 0; i < get_cores_tx(); i++) {
        m_cores_vif[i + 1] = &m_cores_vif_stl[i + 1];
    }

    if (get_dpdk_mode()->dp_rx_queues() ){
        /* multi-queue mode */
        for (int i = 0; i < get_cores_tx(); i++) {
           int qid =(i/get_base_num_cores());   
           int rx_qid=get_dpdk_mode()->get_dp_rx_queues(qid); /* 0,1,2,3*/
           m_cores_vif_stl[i+1].set_rx_queue_id(rx_qid,rx_qid);
       }
    }

    init_vif_cores();

    rx_interactive_conf();
    
    m_stx = new TrexStateless(get_stx_cfg());
    
    start_master_stateless();

    init_stl_stats();
}

COLD_FUNC void CGlobalTRex::init_stl_stats() {
    if (get_dpdk_mode()->dp_rx_queues()) {
        std::vector<TrexStatelessDpCore*> dp_core_ptrs;
        for (int thread_id = 0; thread_id < (int)m_fl.m_threads_info.size(); thread_id++) {
            TrexStatelessDpCore* stl_dp_core = (TrexStatelessDpCore*)m_fl.m_threads_info[thread_id]->get_dp_core();
            dp_core_ptrs.push_back(stl_dp_core);
        }
        get_stateless_obj()->init_stats_multiqueue(dp_core_ptrs);
    } else {
        get_stateless_obj()->init_stats_rx();
    }
}

void CGlobalTRex::init_astf_vif_rx_queues(){
    for (int i = 0; i < get_cores_tx(); i++) {
        int qid =(i/get_base_num_cores());   /* 0,2,3,..*/
        int rx_qid = get_dpdk_mode()->get_dp_rx_queues(qid);
        m_cores_vif_tcp[i+1].set_rx_queue_id(rx_qid,rx_qid);
    }
}

COLD_FUNC void CGlobalTRex::init_astf() {
        
    for (int i = 0; i < get_cores_tx(); i++) {
        m_cores_vif[i + 1] = &m_cores_vif_tcp[i + 1];
    }

    init_vif_cores();
    init_astf_vif_rx_queues();
    rx_interactive_conf();
    
    m_stx = new TrexAstf(get_stx_cfg());
    
    start_master_astf();
}


COLD_FUNC void CGlobalTRex::init_astf_batch() {
    
     for (int i = 0; i < get_cores_tx(); i++) {
        m_cores_vif[i + 1] = &m_cores_vif_tcp[i + 1];
    }
     
     init_vif_cores();
     init_astf_vif_rx_queues();
     rx_batch_conf();
     
     m_stx = new TrexAstfBatch(get_stx_cfg(), &m_mg);
     
     start_master_astf_batch();
}


COLD_FUNC void CGlobalTRex::init_stf() {
    CFlowsYamlInfo  pre_yaml_info;
    
    pre_yaml_info.load_from_yaml_file(CGlobalInfo::m_options.cfg_file);
    if ( isVerbose(0) ){
        CGlobalInfo::m_options.dump(stdout);
        CGlobalInfo::m_memory_cfg.Dump(stdout);
    }
    
    if (pre_yaml_info.m_vlan_info.m_enable) {
        CGlobalInfo::m_options.preview.set_vlan_mode_verify(CPreviewMode::VLAN_MODE_LOAD_BALANCE);
    }
        
    for (int i = 0; i < get_cores_tx(); i++) {
        m_cores_vif[i + 1] = &m_cores_vif_stf[i + 1];
    }
    
    init_vif_cores();
    rx_batch_conf();
        
    m_stx = new TrexStateful(get_stx_cfg(), &m_mg);
    
    start_master_statefull();
}


COLD_FUNC void CGlobalTRex::Delete(){

    m_zmq_publisher.Delete();

    if (m_stx) {
        delete m_stx;
        m_stx = nullptr;
    }

    for (int i = 0; i < m_max_ports; i++) {
        delete m_ports[i]->get_port_attr();
        delete m_ports[i];
    }

    m_fl.Delete();
    m_mg.Delete();
    
    /* imarom: effectively has no meaning as memory is not released (See msg_manager.cpp) */
    CMsgIns::Ins()->Delete();
    delete m_sync_barrier;
}

static bool is_valid_dpdk_limits(struct rte_eth_desc_lim * lim){
    if ((lim->nb_min>0) && (lim->nb_max>0)) {
        return (true);
    }
    return (false);
}

static bool is_val_not_in_range_dpdk_limits(struct rte_eth_desc_lim * lim,
                                        uint16_t val,
                                        uint16_t & new_val){
    if ( lim->nb_max < val ) {
        new_val =  lim->nb_max;
        return (true);
    }
    return (false);
}

COLD_FUNC int  CGlobalTRex::device_prob_init(void){

    if ( isVerbose(0) ) {
       dump_dpdk_devices();
    }

   if (CGlobalInfo::m_options.m_is_vdev) {
      m_max_ports = rte_eth_dev_count() + CGlobalInfo::m_options.m_dummy_count;
    }
    else {
      m_max_ports = port_map.get_max_num_ports();
    }

    if (m_max_ports == 0)
        rte_exit(EXIT_FAILURE, "Error: Could not find supported ethernet ports. You are probably trying to use unsupported NIC \n");

    printf(" Number of ports found: %d", m_max_ports);
    if ( CGlobalInfo::m_options.m_dummy_count ) {
        printf(" (dummy among them: %d)", CGlobalInfo::m_options.m_dummy_count);
    }
    printf("\n");

    if ( m_max_ports %2 !=0 ) {
        rte_exit(EXIT_FAILURE, " Number of ports in config file is %d. It should be even. Please use --limit-ports, or change 'port_limit:' in the config file\n",
                 m_max_ports);
    }

    CParserOption * ps=&CGlobalInfo::m_options;
    if ( ps->get_expected_ports() > TREX_MAX_PORTS ) {
        rte_exit(EXIT_FAILURE, " Maximum number of ports supported is %d. You are trying to use %d. Please use --limit-ports, or change 'port_limit:' in the config file\n"
                 ,TREX_MAX_PORTS, ps->get_expected_ports());
    }

    if ( ps->get_expected_ports() > m_max_ports ){
        rte_exit(EXIT_FAILURE, " There are %d ports available. You are trying to use %d. Please use --limit-ports, or change 'port_limit:' in the config file\n",
                 m_max_ports,
                 ps->get_expected_ports());
    }
    if (ps->get_expected_ports() < m_max_ports ) {
        /* limit the number of ports */
        m_max_ports=ps->get_expected_ports();
    }
    assert(m_max_ports <= TREX_MAX_PORTS);


    if  ( ps->get_number_of_dp_cores_needed() > BP_MAX_CORES ){
        rte_exit(EXIT_FAILURE, " Your configuration require  %d DP cores but the maximum supported is %d - try to reduce `-c value ` or 'c:' in the config file\n",
                 (int)ps->get_number_of_dp_cores_needed(),
                 (int)BP_MAX_CORES);
    }

    int i;
    struct rte_eth_dev_info dev_info, dev_info1;
    bool found_non_dummy = false;

    for (i=0; i<m_max_ports; i++) {
        CTVPort ctvport = CTVPort(i);
        if ( ctvport.is_dummy() ) {
            continue;
        }
        if ( found_non_dummy ) {
            rte_eth_dev_info_get(CTVPort(i).get_repid(),&dev_info1);
            if ( strcmp(dev_info1.driver_name,dev_info.driver_name)!=0) {
                printf(" ERROR all device should have the same type  %s != %s \n",dev_info1.driver_name,dev_info.driver_name);
                exit(1);
            }
        } else {
            found_non_dummy = true;
            rte_eth_dev_info_get(ctvport.get_repid(), &dev_info);
        }
    }

    if ( ps->preview.getVMode() > 0){
        printf("\n\n");
        printf("if_index : %d \n",dev_info.if_index);
        printf("driver name : %s \n",dev_info.driver_name);
        printf("min_rx_bufsize : %d \n",dev_info.min_rx_bufsize);
        printf("max_rx_pktlen  : %d \n",dev_info.max_rx_pktlen);
        printf("max_rx_queues  : %d \n",dev_info.max_rx_queues);
        printf("max_tx_queues  : %d \n",dev_info.max_tx_queues);
        printf("max_mac_addrs  : %d \n",dev_info.max_mac_addrs);

        printf("rx_offload_capa : 0x%lx \n",dev_info.rx_offload_capa);
        printf("tx_offload_capa : 0x%lx \n",dev_info.tx_offload_capa);
        printf("rss reta_size   : %d \n",dev_info.reta_size);
        printf("flow_type_rss   : 0x%lx \n",dev_info.flow_type_rss_offloads);
        printf("tx_desc_max     : %u \n",dev_info.tx_desc_lim.nb_max);
        printf("tx_desc_min     : %u \n",dev_info.tx_desc_lim.nb_min);
        printf("rx_desc_max     : %u \n",dev_info.rx_desc_lim.nb_max);
        printf("rx_desc_min     : %u \n",dev_info.rx_desc_lim.nb_min);
    }

    m_drv = get_ex_drv();

    // check if firmware version is new enough
    for (i = 0; i < m_max_ports; i++) {
        if (m_drv->verify_fw_ver((tvpid_t)i) < 0) {
            // error message printed by verify_fw_ver
            exit(1);
        }
    }

    m_port_cfg.update_var();

    if (m_port_cfg.m_port_conf.rxmode.max_rx_pkt_len > dev_info.max_rx_pktlen ) {
        printf("WARNING: reduce max packet len from %d to %d \n",
               (int)m_port_cfg.m_port_conf.rxmode.max_rx_pkt_len,
               (int)dev_info.max_rx_pktlen);
         m_port_cfg.m_port_conf.rxmode.max_rx_pkt_len = dev_info.max_rx_pktlen;
    }

    uint16_t tx_queues = get_dpdk_mode()->dp_rx_queues();
     int dp_cores = CGlobalInfo::m_options.preview.getCores();

    if ( dev_info.max_tx_queues < tx_queues ) {
        printf("ERROR: driver maximum tx queues is (%d) required (%d) reduce number of cores to support it \n",
               (int)dev_info.max_tx_queues,
               (int)tx_queues);
        exit(1);
    }

    uint16_t rx_queues = get_dpdk_mode()->dp_rx_queues();
    if ( (dev_info.max_rx_queues < rx_queues) || (dp_cores < rx_queues) ) {
        printf("ERROR: driver maximum rx queues is (%d), number of cores (%d) and requested rx queues (%d) is higher, reduce the number of dp cores \n",
               (int)dev_info.max_tx_queues,
               (int)dp_cores,
               (int)rx_queues);
        exit(1);
    }
    

    if ( get_dpdk_mode()->is_hardware_filter_needed() ){
        m_port_cfg.update_global_config_fdir();
    }

    if ( ps->preview.getCores() ==0 ) {
        printf("Error: the number of cores can't be set to 0. Please use -c 1 \n \n");
        exit(1);
    }

    if ( get_dpdk_mode()->is_one_tx_rx_queue() ) {
        /* verify that we have only one thread/core per dual- interface */
        if ( ps->preview.getCores()>1 ) {
            printf("Error: the number of cores should be 1 when the driver support only one tx queue and one rx queue. Please use -c 1 \n");
            exit(1);
        }
    }

    if ( is_valid_dpdk_limits(&dev_info.tx_desc_lim) && 
         is_valid_dpdk_limits(&dev_info.rx_desc_lim)) {
        /* driver support min/max descriptors*/
        CTrexDpdkParams dpdk_p;
        CPlatformYamlInfo *cg = &global_platform_cfg_info;

        get_dpdk_drv_params(dpdk_p);
        if (is_val_not_in_range_dpdk_limits(&dev_info.tx_desc_lim,
                                            dpdk_p.tx_desc_num,
                                            cg->m_tx_desc)){
            printf(" WARNING tx_desc_num was reduced from %d to %d \n",
                   (int)dpdk_p.tx_desc_num,
                   (int)cg->m_tx_desc);
        }
        if (is_val_not_in_range_dpdk_limits(&dev_info.rx_desc_lim,
                                            dpdk_p.rx_desc_num_data_q,
                                            cg->m_rx_desc)){
            printf(" WARNING rx_desc_num was reduced from %d to %d \n",
                   (int)dpdk_p.rx_desc_num_data_q,
                   (int)cg->m_rx_desc);
        }
        if (is_val_not_in_range_dpdk_limits(&dev_info.rx_desc_lim,
                                            dpdk_p.rx_desc_num_dp_q,
                                            cg->m_rx_desc)){
            printf(" WARNING tx_desc_num was reduced from %d to %d \n",
                   (int)dpdk_p.rx_desc_num_dp_q,
                   (int)cg->m_rx_desc);
        }
    }

    return (0);
}

COLD_FUNC int  CGlobalTRex::cores_prob_init(){
    m_max_cores = rte_lcore_count();
    assert(m_max_cores>0);
    return (0);
}

COLD_FUNC int  CGlobalTRex::queues_prob_init(){

    if (m_max_cores < 2) {
        rte_exit(EXIT_FAILURE, "number of cores should be at least 2 \n");
    }
    if ( (m_max_ports>>1) > get_cores_tx() ) {
        rte_exit(EXIT_FAILURE, "You don't have enough physical cores for this configuration dual_ports:%lu physical_cores:%lu dp_cores:%lu check lscpu \n",
                 (ulong)(m_max_ports>>1),
                 (ulong)m_max_cores,
                 (ulong)get_cores_tx());
    }

    assert((m_max_ports>>1) <= get_cores_tx() );

    m_cores_mul = CGlobalInfo::m_options.preview.getCores();

    m_cores_to_dual_ports  = m_cores_mul;

    /* core 0 - control
       -core 1 - port 0/1
       -core 2 - port 2/3
       -core 3 - port 0/1
       -core 4 - port 2/3

       m_cores_to_dual_ports = 2;
    */

    // One q for each core allowed to send on this port + 1 for latency q (Used in stateless) + 1 for RX core.
    m_max_queues_per_port  = m_cores_to_dual_ports + 2;

    if (m_max_queues_per_port > BP_MAX_CORES) {
        rte_exit(EXIT_FAILURE,
                 "Error: Number of TX queues exceeds %d. Try running with lower -c <val> \n",BP_MAX_CORES);
    }

    assert(m_max_queues_per_port>0);
    return (0);
}


COLD_FUNC void CGlobalTRex::dump_config(FILE *fd){
    fprintf(fd," number of ports         : %u \n",m_max_ports);
    fprintf(fd," max cores for 2 ports   : %u \n",m_cores_to_dual_ports);
    fprintf(fd," tx queues per port      : %u \n",m_max_queues_per_port);
}


COLD_FUNC void CGlobalTRex::dump_links_status(FILE *fd){
    for (int i=0; i<m_max_ports; i++) {
        m_ports[i]->get_port_attr()->update_link_status_nowait();
        m_ports[i]->get_port_attr()->dump_link(fd);
    }
}

COLD_FUNC uint16_t CGlobalTRex::get_rx_core_tx_queue_id() {

   if ( !get_dpdk_mode()->is_hardware_filter_needed() ){
       /* not relevant */
       return (INVALID_TX_QUEUE_ID);
   }

    /* 2 spare tx queues per port 
      X is the number of dual_ports  0--x-1 for DP
      
    
       stateless 
       x+0 - DP
       x+1 - rx core ARPs 
       x+2 - low latency 

       STL/ASTF

       x+0 - DP
       x+1 - not used 
       x+2 - rx core, latency 
   */
    
    /* imarom: is this specific to stateless ? */

    if (get_dpdk_mode()->is_dp_latency_tx_queue()) {
        return (m_cores_to_dual_ports); /* stateless */
    } else {
        return (m_cores_to_dual_ports+1);
    }
}

COLD_FUNC uint16_t CGlobalTRex::get_latency_tx_queue_id() {
    /* 2 spare tx queues per port 
      X is the number of dual_ports  0--x-1 for DP


       stateless 
       x+0 - DP
       x+1 - rx core ARPs 
       x+2 - low latency 

       STL/ASTF

       x+0 - DP
       x+1 - not used 
       x+2 - rx core, latency 
   */
    
    /* imarom: is this specific to stateless ? */
    if (get_is_stateless()) {
        return (m_cores_to_dual_ports+1);
    } else {
        return (CCoreEthIF::INVALID_Q_ID);
    }
}


COLD_FUNC bool CGlobalTRex::lookup_port_by_mac(const uint8_t *mac, uint8_t &port_id) {
    for (int i = 0; i < m_max_ports; i++) {
        if ( m_ports[i]->is_dummy() ) {
            continue;
        }
        if (memcmp((char *)CGlobalInfo::m_options.get_src_mac_addr(i), mac, 6) == 0) {
            port_id = i;
            return true;
        }
    }

    return false;
}

COLD_FUNC void CGlobalTRex::dump_post_test_stats(FILE *fd){
    uint64_t pkt_out=0;
    uint64_t pkt_out_bytes=0;
    uint64_t pkt_in_bytes=0;
    uint64_t pkt_in=0;
    uint64_t sw_pkt_out=0;
    uint64_t sw_pkt_out_err=0;
    uint64_t sw_pkt_out_bytes=0;
    uint64_t tx_arp = 0;
    uint64_t rx_arp = 0;

    int i;
    for (i=0; i<get_cores_tx(); i++) {
        CCoreEthIF * erf_vif = m_cores_vif[i+1];
        CVirtualIFPerSideStats stats;
        erf_vif->GetCoreCounters(&stats);
        sw_pkt_out     += stats.m_tx_pkt;
        sw_pkt_out_err += stats.m_tx_drop +stats.m_tx_queue_full +stats.m_tx_alloc_error+stats.m_tx_redirect_error ;
        sw_pkt_out_bytes +=stats.m_tx_bytes;
    }


    for (i=0; i<m_max_ports; i++) {
        CPhyEthIF * _if=m_ports[i];
        pkt_in  +=_if->get_stats().ipackets;
        pkt_in_bytes +=_if->get_stats().ibytes;
        pkt_out +=_if->get_stats().opackets;
        pkt_out_bytes +=_if->get_stats().obytes;
        tx_arp += _if->get_ignore_stats().get_tx_arp();
        rx_arp += _if->get_ignore_stats().get_rx_arp();
    }
    if ( CGlobalInfo::m_options.is_latency_enabled() ){
        sw_pkt_out += m_mg.get_total_pkt();
        sw_pkt_out_bytes +=m_mg.get_total_bytes();
    }


    fprintf (fd," summary stats \n");
    fprintf (fd," -------------- \n");

    if (pkt_in > pkt_out)
        {
            fprintf (fd, " Total-pkt-drop       : 0 pkts \n");
            if (pkt_in > pkt_out * 1.01)
                fprintf (fd, " Warning : number of rx packets exceeds 101%% of tx packets!\n");
        }
    else
        fprintf (fd, " Total-pkt-drop       : %llu pkts \n", (unsigned long long) (pkt_out - pkt_in));
    for (i=0; i<m_max_ports; i++) {
        if ( m_stats.m_port[i].m_link_was_down ) {
            fprintf (fd, " WARNING: Link was down at port %d during test (at least for some time)!\n", i);
        }
    }
    fprintf (fd," Total-tx-bytes       : %llu bytes \n", (unsigned long long)pkt_out_bytes);
    fprintf (fd," Total-tx-sw-bytes    : %llu bytes \n", (unsigned long long)sw_pkt_out_bytes);
    fprintf (fd," Total-rx-bytes       : %llu byte \n", (unsigned long long)pkt_in_bytes);

    fprintf (fd," \n");

    fprintf (fd," Total-tx-pkt         : %llu pkts \n", (unsigned long long)pkt_out);
    fprintf (fd," Total-rx-pkt         : %llu pkts \n", (unsigned long long)pkt_in);
    fprintf (fd," Total-sw-tx-pkt      : %llu pkts \n", (unsigned long long)sw_pkt_out);
    fprintf (fd," Total-sw-err         : %llu pkts \n", (unsigned long long)sw_pkt_out_err);
    fprintf (fd," Total ARP sent       : %llu pkts \n", (unsigned long long)tx_arp);
    fprintf (fd," Total ARP received   : %llu pkts \n", (unsigned long long)rx_arp);


    if ( CGlobalInfo::m_options.is_latency_enabled() ){
        fprintf (fd," maximum-latency   : %.0f usec \n",m_mg.get_max_latency());
        fprintf (fd," average-latency   : %.0f usec \n",m_mg.get_avr_latency());
        fprintf (fd," latency-any-error : %s  \n",m_mg.is_any_error()?"ERROR":"OK");
    }


}


COLD_FUNC void CGlobalTRex::update_stats(){

    int i;
    for (i=0; i<m_max_ports; i++) {
        CPhyEthIF * _if=m_ports[i];
        _if->update_counters();
    }
    uint64_t total_open_flows=0;


    CFlowGenListPerThread   * lpt;
    for (i=0; i<get_cores_tx(); i++) {
        lpt = m_fl.m_threads_info[i];
        total_open_flows +=   lpt->m_stats.m_total_open_flows ;
    }
    m_last_total_cps = m_cps.add(total_open_flows);

    bool all_init=true;
    vector<CSTTCp *> sttcp_list;
    TrexAstf* stx = 0;
    if ( get_is_interactive() && get_is_tcp_mode() ) {
        stx = get_astf_object();
        sttcp_list = stx->get_sttcp_list();
    }
    else if ( m_fl.m_stt_cp ) {
        sttcp_list.push_back(m_fl.m_stt_cp);
    }
    for ( auto lpstt : sttcp_list ) {
        if (!lpstt->m_init){
            /* check that we have all objects;*/
            for (i=0; i<get_cores_tx(); i++) {
                lpt = m_fl.m_threads_info[i];
                if ( (lpt->m_c_tcp==0) ||(lpt->m_s_tcp==0) ){
                    all_init=false;
                    break;
                }
            }
            if (all_init) {
                for (i=0; i<get_cores_tx(); i++) {
                    lpt = m_fl.m_threads_info[i];
                    lpstt->Add(TCP_CLIENT_SIDE, lpt->m_c_tcp);
                    lpstt->Add(TCP_SERVER_SIDE, lpt->m_s_tcp);
                }
                lpstt->Init();
                lpstt->m_init=true;
            }
        }

        if (lpstt->m_init){
            if (lpstt->need_profile_ctx_update()) {
                if (!stx || (stx && stx->is_safe_update_stats())) {
                    lpstt->update_profile_ctx();
                }
            }
            lpstt->Update();
        }
    }
}

COLD_FUNC tx_per_flow_t CGlobalTRex::get_flow_tx_stats(uint8_t port, uint16_t index) {
    return m_stats.m_port[port].m_tx_per_flow[index] - m_stats.m_port[port].m_prev_tx_per_flow[index];
}

// read stats. Return read value, and clear.
COLD_FUNC tx_per_flow_t CGlobalTRex::clear_flow_tx_stats(uint8_t port, uint16_t index, bool is_lat) {
    uint8_t port0;
    CFlowGenListPerThread * lpt;
    tx_per_flow_t ret;

    m_stats.m_port[port].m_tx_per_flow[index].clear();

    for (int i=0; i < get_cores_tx(); i++) {
        lpt = m_fl.m_threads_info[i];
        port0 = lpt->getDualPortId() * 2;
        if ((port == port0) || (port == port0 + 1)) {
            m_stats.m_port[port].m_tx_per_flow[index] +=
                lpt->m_node_gen.m_v_if->get_stats()[port - port0].m_tx_per_flow[index];
            if (is_lat)
                lpt->m_node_gen.m_v_if->get_stats()[port - port0].m_lat_data[index - MAX_FLOW_STATS].reset();
        }
    }

    ret = m_stats.m_port[port].m_tx_per_flow[index] - m_stats.m_port[port].m_prev_tx_per_flow[index];

    // Since we return diff from prev, following "clears" the stats.
    m_stats.m_port[port].m_prev_tx_per_flow[index] = m_stats.m_port[port].m_tx_per_flow[index];

    return ret;
}

COLD_FUNC
void CGlobalTRex::get_stats(CGlobalStats & stats){

    int i;
    float total_tx=0.0;
    float total_rx=0.0;
    float total_tx_pps=0.0;
    float total_rx_pps=0.0;

    stats.m_total_tx_pkts       = 0;
    stats.m_total_rx_pkts       = 0;
    stats.m_total_tx_bytes      = 0;
    stats.m_total_rx_bytes      = 0;
    stats.m_total_alloc_error   = 0;
    stats.m_total_queue_full    = 0;
    stats.m_total_queue_drop    = 0;
    stats.m_rx_core_pps         = 0.0;

    stats.m_num_of_ports = m_max_ports;
    stats.m_cpu_util = m_fl.GetCpuUtil();
    stats.m_cpu_util_raw = m_fl.GetCpuUtilRaw();

    stats.m_rx_cpu_util = m_stx->get_rx()->get_cpu_util();
    stats.m_rx_core_pps = m_stx->get_rx()->get_pps_rate();
        
    stats.m_threads      = m_fl.m_threads_info.size();

    for (i=0; i<m_max_ports; i++) {
        CPhyEthIF * _if=m_ports[i];
        CPerPortStats * stp=&stats.m_port[i];

        CPhyEthIFStats & st =_if->get_stats();

        stp->opackets = st.opackets;
        stp->obytes   = st.obytes;
        stp->ipackets = st.ipackets;
        stp->ibytes   = st.ibytes;
        stp->ierrors  = st.ierrors;
        stp->oerrors  = st.oerrors;
        stp->m_total_tx_bps = _if->get_last_tx_rate()*_1Mb_DOUBLE;
        stp->m_total_tx_pps = _if->get_last_tx_pps_rate();
        stp->m_total_rx_bps = _if->get_last_rx_rate()*_1Mb_DOUBLE;
        stp->m_total_rx_pps = _if->get_last_rx_pps_rate();
        stp->m_link_up        = _if->get_port_attr()->is_link_up();
        stp->m_link_was_down |= ! _if->get_port_attr()->is_link_up();

        stats.m_total_tx_pkts  += st.opackets;
        stats.m_total_rx_pkts  += st.ipackets;
        stats.m_total_tx_bytes += st.obytes;
        stats.m_total_rx_bytes += st.ibytes;

        total_tx +=_if->get_last_tx_rate();
        total_rx +=_if->get_last_rx_rate();
        total_tx_pps +=_if->get_last_tx_pps_rate();
        total_rx_pps +=_if->get_last_rx_pps_rate();
        // IP ID rules
        for (int flow = 0; flow <= CFlowStatRuleMgr::instance()->get_max_hw_id(); flow++) {
            stats.m_port[i].m_tx_per_flow[flow].clear();
        }
        // payload rules
        for (int flow = MAX_FLOW_STATS; flow <= MAX_FLOW_STATS
                 + CFlowStatRuleMgr::instance()->get_max_hw_id_payload(); flow++) {
            stats.m_port[i].m_tx_per_flow[flow].clear();
        }

        stp->m_cpu_util = get_cpu_util_per_interface(i);

    }

    uint64_t total_open_flows=0;
    uint64_t total_active_flows=0;

    uint64_t total_clients=0;
    uint64_t total_servers=0;
    uint64_t active_sockets=0;
    uint64_t total_sockets=0;


    uint64_t total_nat_time_out =0;
    uint64_t total_nat_time_out_wait_ack =0;
    uint64_t total_nat_no_fid   =0;
    uint64_t total_nat_active   =0;
    uint64_t total_nat_syn_wait = 0;
    uint64_t total_nat_open     =0;
    uint64_t total_nat_learn_error=0;

    CFlowGenListPerThread   * lpt;
    stats.m_template.Clear();

    bool can_read_tuple_gen = true;
    if ( get_is_interactive() && get_is_tcp_mode() ) {
        TrexAstf *astf_stx = (TrexAstf*) m_stx;
        if ( astf_stx->get_state() != TrexAstf::STATE_TX ) {
            can_read_tuple_gen = false;
        }
    }

    for (i=0; i<get_cores_tx(); i++) {
        lpt = m_fl.m_threads_info[i];
        total_open_flows +=   lpt->m_stats.m_total_open_flows ;
        total_active_flows += (lpt->m_stats.m_total_open_flows-lpt->m_stats.m_total_close_flows) ;

        stats.m_total_alloc_error += lpt->m_node_gen.m_v_if->get_stats()[0].m_tx_alloc_error+
            lpt->m_node_gen.m_v_if->get_stats()[1].m_tx_alloc_error;
        stats.m_total_queue_full +=lpt->m_node_gen.m_v_if->get_stats()[0].m_tx_queue_full+
            lpt->m_node_gen.m_v_if->get_stats()[1].m_tx_queue_full;

        stats.m_total_queue_drop +=lpt->m_node_gen.m_v_if->get_stats()[0].m_tx_drop+
            lpt->m_node_gen.m_v_if->get_stats()[1].m_tx_drop;

        stats.m_template.Add(&lpt->m_node_gen.m_v_if->get_stats()[0].m_template);
        stats.m_template.Add(&lpt->m_node_gen.m_v_if->get_stats()[1].m_template);

        if ( can_read_tuple_gen ) {
            total_clients   += lpt->m_smart_gen.getTotalClients();
            total_servers   += lpt->m_smart_gen.getTotalServers();
            active_sockets  += lpt->m_smart_gen.ActiveSockets();
            total_sockets   += lpt->m_smart_gen.MaxSockets();
        }

        total_nat_time_out +=lpt->m_stats.m_nat_flow_timeout;
        total_nat_time_out_wait_ack += lpt->m_stats.m_nat_flow_timeout_wait_ack;
        total_nat_no_fid   +=lpt->m_stats.m_nat_lookup_no_flow_id ;
        total_nat_active   +=lpt->m_stats.m_nat_lookup_add_flow_id - lpt->m_stats.m_nat_lookup_remove_flow_id;
        total_nat_syn_wait += lpt->m_stats.m_nat_lookup_add_flow_id - lpt->m_stats.m_nat_lookup_wait_ack_state;
        total_nat_open     +=lpt->m_stats.m_nat_lookup_add_flow_id;
        total_nat_learn_error   +=lpt->m_stats.m_nat_flow_learn_error;
        uint8_t port0 = lpt->getDualPortId() *2;
        // IP ID rules
        for (int flow = 0; flow <= CFlowStatRuleMgr::instance()->get_max_hw_id(); flow++) {
            stats.m_port[port0].m_tx_per_flow[flow] +=
                lpt->m_node_gen.m_v_if->get_stats()[0].m_tx_per_flow[flow];
            stats.m_port[port0 + 1].m_tx_per_flow[flow] +=
                lpt->m_node_gen.m_v_if->get_stats()[1].m_tx_per_flow[flow];
        }
        // payload rules
        for (int flow = MAX_FLOW_STATS; flow <= MAX_FLOW_STATS
                 + CFlowStatRuleMgr::instance()->get_max_hw_id_payload(); flow++) {
            stats.m_port[port0].m_tx_per_flow[flow] +=
                lpt->m_node_gen.m_v_if->get_stats()[0].m_tx_per_flow[flow];
            stats.m_port[port0 + 1].m_tx_per_flow[flow] +=
                lpt->m_node_gen.m_v_if->get_stats()[1].m_tx_per_flow[flow];
        }

    }

    stats.m_total_nat_time_out = total_nat_time_out;
    stats.m_total_nat_time_out_wait_ack = total_nat_time_out_wait_ack;
    stats.m_total_nat_no_fid   = total_nat_no_fid;
    stats.m_total_nat_active   = total_nat_active;
    stats.m_total_nat_syn_wait = total_nat_syn_wait;
    stats.m_total_nat_open     = total_nat_open;
    stats.m_total_nat_learn_error     = total_nat_learn_error;

    stats.m_total_clients = total_clients;
    stats.m_total_servers = total_servers;
    stats.m_active_sockets = active_sockets;

    if (total_sockets != 0) {
        stats.m_socket_util =100.0*(double)active_sockets/(double)total_sockets;
    } else {
        stats.m_socket_util = 0;
    }



    float drop_rate=total_tx-total_rx;
    if ( (drop_rate<0.0)  || (drop_rate < 0.1*total_tx ) )  {
        drop_rate=0.0;
    }
    float pf =CGlobalInfo::m_options.m_platform_factor;
    stats.m_platform_factor = pf;

    stats.m_active_flows = total_active_flows*pf;
    stats.m_open_flows   = total_open_flows*pf;
    stats.m_rx_drop_bps   = drop_rate*pf *_1Mb_DOUBLE;

    stats.m_tx_bps        = total_tx*pf*_1Mb_DOUBLE;
    stats.m_rx_bps        = total_rx*pf*_1Mb_DOUBLE;
    stats.m_tx_pps        = total_tx_pps*pf;
    stats.m_rx_pps        = total_rx_pps*pf;
    stats.m_tx_cps        = m_last_total_cps*pf;
    if(stats.m_cpu_util < 0.0001)
        stats.m_bw_per_core = 0;
    else
        stats.m_bw_per_core   = 2*(stats.m_tx_bps/1e9)*100.0/(stats.m_cpu_util*stats.m_threads);

#if 0
    if ((m_expected_cps == 0) && get_is_tcp_mode()) {
        // In astf mode, we know the info only after doing first get of data from json (which triggers analyzing the data)
        m_expected_cps = CAstfDB::instance()->get_expected_cps();
        m_expected_bps = CAstfDB::instance()->get_expected_bps();
    }
#endif

    stats.m_tx_expected_cps        = m_expected_cps*pf;
    stats.m_tx_expected_pps        = m_expected_pps*pf;
    stats.m_tx_expected_bps        = m_expected_bps*pf;
}

COLD_FUNC float
CGlobalTRex::get_cpu_util_per_interface(uint8_t port_id) {
    CPhyEthIF * _if = m_ports[port_id];

    float    tmp = 0;
    uint8_t  cnt = 0;
    for (const auto &p : _if->get_core_list()) {
        uint8_t core_id = p.first;
        CFlowGenListPerThread *lp = m_fl.m_threads_info[core_id];
        if (lp->is_port_active(port_id)) {
            tmp += lp->m_cpu_cp_u.GetVal();
            cnt++;
        }
    }

    return ( (cnt > 0) ? (tmp / cnt) : 0);

}

COLD_FUNC
COLD_FUNC bool CGlobalTRex::sanity_check(){

    if ( !get_is_interactive() ) {
        CFlowGenListPerThread   * lpt;
        uint32_t errors=0;
        int i;
        for (i=0; i<get_cores_tx(); i++) {
            lpt = m_fl.m_threads_info[i];
            errors   += lpt->m_smart_gen.getErrorAllocationCounter();
        }

        if ( errors && (get_is_tcp_mode()==false) ) {
            m_mark_not_enogth_clients = true;
            printf(" ERROR can't allocate tuple, not enough clients \n");
            printf(" you should allocate more clients in the pool \n");

            /* mark test end and get out */
            mark_for_shutdown(SHUTDOWN_NOT_ENOGTH_CLIENTS);

            return(true);
        }
    }

    return ( false);
}


/* dump the template info */
COLD_FUNC void CGlobalTRex::dump_template_info(std::string & json){
    CFlowGenListPerThread   * lpt = m_fl.m_threads_info[0];
    CFlowsYamlInfo * yaml_info=&lpt->m_yaml_info;
    if ( yaml_info->is_any_template()==false){ 
        json="";
        return;
    }

    json="{\"name\":\"template_info\",\"type\":0,\"data\":[";
    int i;
    for (i=0; i<yaml_info->m_vec.size()-1; i++) {
        CFlowYamlInfo * r=&yaml_info->m_vec[i] ;
        json+="\""+ r->m_name+"\"";
        json+=",";
    }
    json+="\""+yaml_info->m_vec[i].m_name+"\"";
    json+="]}" ;
}

COLD_FUNC void CGlobalTRex::dump_stats(FILE *fd, CGlobalStats::DumpFormat format){

    sync_threads_stats();

    if (format==CGlobalStats::dmpTABLE) {
        if ( m_io_modes.m_g_mode == CTrexGlobalIoMode::gNORMAL ){
            switch (m_io_modes.m_pp_mode ){
            case CTrexGlobalIoMode::ppDISABLE:
                fprintf(fd,"\n+Per port stats disabled \n");
                break;
            case CTrexGlobalIoMode::ppTABLE:
                fprintf(fd,"\n-Per port stats table \n");
                m_stats.Dump(fd,CGlobalStats::dmpTABLE);
                break;
            case CTrexGlobalIoMode::ppSTANDARD:
                fprintf(fd,"\n-Per port stats - standard\n");
                m_stats.Dump(fd,CGlobalStats::dmpSTANDARD);
                break;
            };

            switch (m_io_modes.m_ap_mode ){
            case   CTrexGlobalIoMode::apDISABLE:
                fprintf(fd,"\n+Global stats disabled \n");
                break;
            case   CTrexGlobalIoMode::apENABLE:
                fprintf(fd,"\n-Global stats enabled \n");
                m_stats.DumpAllPorts(fd);
                break;
            };
        }
    }else{
        /* at exit , always need to dump it in standartd mode for scripts*/
        m_stats.Dump(fd,format);
        m_stats.DumpAllPorts(fd);
    }

}

COLD_FUNC void CGlobalTRex::sync_threads_stats() {
    update_stats();
    get_stats(m_stats);
}

COLD_FUNC void
CGlobalTRex::publish_async_data(bool sync_now, bool baseline) {
    std::string json;

    if (sync_now) {
        sync_threads_stats();
    }

    /* common stats */
    m_stats.dump_json(json, baseline);
    m_zmq_publisher.publish_json(json);

    /* generator json , all cores are the same just sample the first one */
    m_fl.m_threads_info[0]->m_node_gen.dump_json(json);
    m_zmq_publisher.publish_json(json);

    /* config specific stats */
    m_stx->publish_async_data();
}


COLD_FUNC void
CGlobalTRex::publish_async_barrier(uint32_t key) {
    m_zmq_publisher.publish_barrier(key);
}

COLD_FUNC void CGlobalTRex:: publish_async_port_attr_changed(uint8_t port_id) {
    Json::Value data;
    data["port_id"] = port_id;
    TRexPortAttr * _attr = m_ports[port_id]->get_port_attr();

    _attr->to_json(data["attr"]);

    m_zmq_publisher.publish_event(TrexPublisher::EVENT_PORT_ATTR_CHANGED, data);
}


COLD_FUNC void CGlobalTRex::global_stats_to_json(Json::Value &output) {
    sync_threads_stats();
    m_stats.global_stats_to_json(output);
}

COLD_FUNC void CGlobalTRex::port_stats_to_json(Json::Value &output, uint8_t port_id) {
    sync_threads_stats();
    m_stats.port_stats_to_json(output, port_id);
}


COLD_FUNC void CGlobalTRex::check_for_ports_link_change() {
    
    // update speed, link up/down etc.
    for (int i=0; i<m_max_ports; i++) {
        bool changed = m_ports[i]->get_port_attr()->update_link_status_nowait();
        if (changed) {
            publish_async_port_attr_changed(i);
        }
    }

}

COLD_FUNC void CGlobalTRex::check_for_io() {
    /* is IO allowed ? - if not, get out */
    if (CGlobalInfo::m_options.preview.get_no_keyboard()) {
        return;
    }
    
    bool rc = m_io_modes.handle_io_modes();
    if (rc) {
        mark_for_shutdown(SHUTDOWN_CTRL_C);
        return;
    }
    
}


COLD_FUNC void
 CGlobalTRex::show_panel() {

    if (m_io_modes.m_g_mode != CTrexGlobalIoMode::gDISABLE ) {
        fprintf(stdout,"\033[2J");
        fprintf(stdout,"\033[2H");

    } else {
        if ( m_io_modes.m_g_disable_first  ) {
            m_io_modes.m_g_disable_first=false;
            fprintf(stdout,"\033[2J");
            fprintf(stdout,"\033[2H");
            printf("clean !!!\n");
            fflush(stdout);
        }
    }


    if (m_io_modes.m_g_mode == CTrexGlobalIoMode::gHELP ) {
        m_io_modes.DumpHelp(stdout);
    }

    dump_stats(stdout,CGlobalStats::dmpTABLE);

    if (m_io_modes.m_g_mode == CTrexGlobalIoMode::gNORMAL ) {
        fprintf (stdout," current time    : %.1f sec  \n",now_sec());
        float d= CGlobalInfo::m_options.m_duration - now_sec();
        if (d<0) {
            d=0;

        }
        fprintf (stdout," test duration   : %.1f sec  \n",d);
    }

    /* TCP stats */
    if (m_io_modes.m_g_mode == CTrexGlobalIoMode::gSTT) {
        vector<CSTTCp *> sttcp_list;
        if ( get_is_interactive() && get_is_tcp_mode() ) {
            sttcp_list = get_astf_object()->get_sttcp_list();
        }
        else if ( m_fl.m_stt_cp ) {
            sttcp_list.push_back(m_fl.m_stt_cp);
        }
        for ( auto lpstt : sttcp_list ) {
            if (lpstt->m_init) {
                lpstt->DumpTable();
            }
        }
    }

    if (m_io_modes.m_g_mode == CTrexGlobalIoMode::gMem) {

        if ( m_stats_cnt%4==0) {
            fprintf (stdout," %s \n",CGlobalInfo::dump_pool_as_json_str().c_str());
        }
    }


    if ( CGlobalInfo::m_options.is_rx_enabled() && (! get_is_stateless())) {
        m_mg.update();

        if ( m_io_modes.m_g_mode ==  CTrexGlobalIoMode::gNORMAL ) {
            if (CGlobalInfo::m_options.m_latency_rate != 0) {
                switch (m_io_modes.m_l_mode) {
                case CTrexGlobalIoMode::lDISABLE:
                    fprintf(stdout, "\n+Latency stats disabled \n");
                    break;
                case CTrexGlobalIoMode::lENABLE:
                    fprintf(stdout, "\n-Latency stats enabled \n");
                    m_mg.DumpShort(stdout);
                    break;
                case CTrexGlobalIoMode::lENABLE_Extended:
                    fprintf(stdout, "\n-Latency stats extended \n");
                    m_mg.Dump(stdout);
                    break;
                }
            }

            if ( get_is_rx_check_mode() ) {

                switch (m_io_modes.m_rc_mode) {
                case CTrexGlobalIoMode::rcDISABLE:
                    fprintf(stdout,"\n+Rx Check stats disabled \n");
                    break;
                case CTrexGlobalIoMode::rcENABLE:
                    fprintf(stdout,"\n-Rx Check stats enabled \n");
                    m_mg.DumpShortRxCheck(stdout);
                    break;
                case CTrexGlobalIoMode::rcENABLE_Extended:
                    fprintf(stdout,"\n-Rx Check stats enhanced \n");
                    m_mg.DumpRxCheck(stdout);
                    break;
                }
            }
        }
    }
    if ( m_io_modes.m_g_mode ==  CTrexGlobalIoMode::gNAT ) {
        if ( m_io_modes.m_nat_mode == CTrexGlobalIoMode::natENABLE ) {
            if (CGlobalInfo::is_learn_mode(CParserOption::LEARN_MODE_TCP_ACK)) {
                fprintf(stdout, "NAT flow table info\n");
                m_mg.dump_nat_flow_table(stdout);
            } else {
                fprintf(stdout, "\nThis is only relevant in --learn-mode %d\n", CParserOption::LEARN_MODE_TCP_ACK);
            }
        }
    }


}

COLD_FUNC void CGlobalTRex::handle_slow_path() {
  m_stats_cnt++;

  /* sanity checks */
  sanity_check();

  /* handle port link changes */
  check_for_ports_link_change();

  /* keyboard input */
  check_for_io();

  /* based on the panel chosen, show it */
  show_panel();

  /* publish data */
  publish_async_data(false);

  /* provide the STX object a tick (used by implementing objects) */
  m_stx->slowpath_tick();
}

COLD_FUNC void CGlobalTRex::handle_fast_path() {

  /* pass fast path tick to the polymorphic object */
  m_stx->fastpath_tick();

  /* measure CPU utilization by sampling (we sample 1000 to get an accurate
   * sampling) */
  for (int i = 0; i < 1000; i++) {
    m_fl.UpdateFast();
    rte_pause();
  }

  /* in case of batch, when all DP cores are done, mark for shutdown */
  if (is_all_dp_cores_finished()) {
    mark_for_shutdown(SHUTDOWN_TEST_ENDED);
  }
}

/**
 * shutdown sequence
 *
 */
COLD_FUNC void CGlobalTRex::shutdown() {
    std::stringstream ss;

    assert(is_marked_for_shutdown());

    ss << " *** TRex is shutting down - cause: '";

    ss << get_shutdown_cause();

    ss << "'";

    /* report */
    std::cout << ss.str() << "\n";

    /* first stop the WD */
    TrexWatchDog::getInstance().stop();

    /* interactive shutdown */
    m_stx->shutdown();

    wait_for_all_cores();

    /* shutdown drivers */
    for (int i = 0; i < m_max_ports; i++) {
        m_ports[i]->stop();
    }

    if (m_mark_for_shutdown != SHUTDOWN_TEST_ENDED) {
        /* we should stop latency and exit to stop agents */
        Delete();
        if (!CGlobalInfo::m_options.preview.get_is_termio_disabled()) {
            utl_termio_reset();
        }
        exit(-1);
    }
}



COLD_FUNC int CGlobalTRex::run_in_rx_core(void){

    CPreviewMode *lp = &CGlobalInfo::m_options.preview;

    rte_thread_setname(pthread_self(), "TRex RX");

    /* set RT mode if set */
    if (lp->get_rt_prio_mode()) {
        struct sched_param param;
        param.sched_priority = sched_get_priority_max(SCHED_FIFO);
        if (pthread_setschedparam(pthread_self(), SCHED_FIFO, &param) != 0) {
            perror("setting RT priroity mode on RX core failed with error");
            exit(EXIT_FAILURE);
        }
    }

    /* will block until RX core is signaled to stop */
    m_stx->get_rx()->start();
  
    return (0);
}

COLD_FUNC int CGlobalTRex::run_in_core(virtual_thread_id_t virt_core_id){
    std::stringstream ss;
    CPreviewMode *lp = &CGlobalInfo::m_options.preview;

    ss << "Trex DP core " << int(virt_core_id);
    rte_thread_setname(pthread_self(), ss.str().c_str());

    /* set RT mode if set */
    if (lp->get_rt_prio_mode()) {
        struct sched_param param;
        param.sched_priority = sched_get_priority_max(SCHED_FIFO);
        if (pthread_setschedparam(pthread_self(), SCHED_FIFO, &param) != 0) {
            perror("setting RT priroity mode on DP core failed with error");
            exit(EXIT_FAILURE);
        }
    }


    if ( lp->getSingleCore() &&
         (virt_core_id==2 ) &&
         (lp-> getCores() ==1) ){
        printf(" bypass this core \n");
        m_signal[virt_core_id]=1;
        return (0);
    }


    assert(m_fl_was_init);
    CFlowGenListPerThread   * lpt;

    lpt = m_fl.m_threads_info[virt_core_id-1];

    /* register a watchdog handle on current core */
    lpt->m_monitor.create(ss.str(), 1);
    TrexWatchDog::getInstance().register_monitor(&lpt->m_monitor);

    lpt->start(CGlobalInfo::m_options.out_file, *lp);
    
    /* done - remove this from the watchdog (we might wait on join for a long time) */
    lpt->m_monitor.disable();

    m_signal[virt_core_id]=1;
    return (0);
}


COLD_FUNC int CGlobalTRex::stop_master(){

    delay(1000);
    fprintf(stdout," ==================\n");
    fprintf(stdout," interface sum \n");
    fprintf(stdout," ==================\n");
    dump_stats(stdout,CGlobalStats::dmpSTANDARD);
    fprintf(stdout," ==================\n");
    fprintf(stdout," \n\n");

    fprintf(stdout," ==================\n");
    fprintf(stdout," interface sum \n");
    fprintf(stdout," ==================\n");

    CFlowGenListPerThread   * lpt;
    uint64_t total_tx_rx_check=0;

    int i;
    for (i=0; i<get_cores_tx(); i++) {
        lpt = m_fl.m_threads_info[i];
        CCoreEthIF * erf_vif = m_cores_vif[i+1];

        erf_vif->DumpCoreStats(stdout);
        erf_vif->DumpIfStats(stdout);
        total_tx_rx_check+=erf_vif->get_stats()[CLIENT_SIDE].m_tx_rx_check_pkt+
            erf_vif->get_stats()[SERVER_SIDE].m_tx_rx_check_pkt;
    }

    fprintf(stdout," ==================\n");
    fprintf(stdout," generators \n");
    fprintf(stdout," ==================\n");
    for (i=0; i<get_cores_tx(); i++) {
        lpt = m_fl.m_threads_info[i];
        lpt->m_node_gen.DumpHist(stdout);
        lpt->DumpStats(stdout);
    }
    if ( CGlobalInfo::m_options.is_latency_enabled() ){
        fprintf(stdout," ==================\n");
        fprintf(stdout," latency \n");
        fprintf(stdout," ==================\n");
        m_mg.DumpShort(stdout);
        m_mg.Dump(stdout);
        m_mg.DumpShortRxCheck(stdout);
        m_mg.DumpRxCheck(stdout);
        m_mg.DumpRxCheckVerification(stdout,total_tx_rx_check);
    }

    dump_stats(stdout,CGlobalStats::dmpSTANDARD);
    dump_post_test_stats(stdout);

    vector<CSTTCp *> sttcp_list;
    if ( get_is_interactive() && get_is_tcp_mode() ) {
        sttcp_list = get_astf_object()->get_sttcp_list();
    }
    else if ( m_fl.m_stt_cp ) {
        sttcp_list.push_back(m_fl.m_stt_cp);
    }
    for ( auto lpstt : sttcp_list ) {
        assert(lpstt);
        assert(lpstt->m_init);
        lpstt->DumpTable();
    }

    publish_async_data(false);

    if (m_mark_not_enogth_clients) {
        printf("ERROR: there are not enogth clients for this rate, try to add more clients to the pool ! \n");
    }

    return (0);
}


COLD_FUNC bool CGlobalTRex::is_all_dp_cores_finished() {
    for (int i = 0; i < get_cores_tx(); i++) {
        if (m_signal[i+1]==0) {
            return false;
        }
    }
    
    return true;
}

COLD_FUNC bool CGlobalTRex::is_all_cores_finished() {
    
    /* DP cores */
    if (!is_all_dp_cores_finished()) {
        return false;
    }
    
    /* RX core */
    if (m_stx->get_rx()->is_active()) {
        return false;
    }

    return true;
}


COLD_FUNC int CGlobalTRex::start_master_stateless(){
    int i;
    for (i=0; i<BP_MAX_CORES; i++) {
        m_signal[i]=0;
    }
    m_fl.Create();
    m_expected_pps = 0;
    m_expected_cps = 0;
    m_expected_bps = 0;

    m_fl.generate_p_thread_info(get_cores_tx());
    CFlowGenListPerThread   * lpt;

    for (i=0; i<get_cores_tx(); i++) {
        lpt = m_fl.m_threads_info[i];
        CVirtualIF * erf_vif = m_cores_vif[i+1];
        lpt->set_vif(erf_vif);
        lpt->set_sync_barrier(m_sync_barrier);
    }
    m_fl_was_init=true;

    return (0);
}


COLD_FUNC int CGlobalTRex::start_master_astf_common() {
    for (int i = 0; i < BP_MAX_CORES; i++) {
        m_signal[i] = 0;
    }

    m_fl.Create();
    m_fl.load_astf();


    m_expected_pps = 0; // Can't know this in astf mode.
    // two below are computed later. Need to do this after analyzing data read from json.
    m_expected_cps = 0;
    m_expected_bps = 0;


    m_fl.generate_p_thread_info(get_cores_tx());

    for (int i = 0; i < get_cores_tx(); i++) {
        CFlowGenListPerThread *lpt = m_fl.m_threads_info[i];
        CVirtualIF *erf_vif = m_cores_vif[i+1];
        lpt->set_vif(erf_vif);
        lpt->set_sync_barrier(m_sync_barrier);
    }

    m_fl_was_init = true;

    return (0);
}


COLD_FUNC int CGlobalTRex::start_master_astf_batch() {

    std::string json_file_name = "/tmp/astf";
    if (CGlobalInfo::m_options.prefix.size() != 0) {
        json_file_name += "-" + CGlobalInfo::m_options.prefix;
    }
    json_file_name += ".json";

    fprintf(stdout, "Using json file %s\n", json_file_name.c_str());

    CAstfDB * db=CAstfDB::instance();
    /* load json */
    if (! db->parse_file(json_file_name) ) {
       exit(-1);
    }

    CTupleGenYamlInfo  tuple_info;
    db->get_tuple_info(tuple_info);

    start_master_astf_common();

    /* client config for ASTF this is a patch.. we would need to remove this in interactive mode */
    if (CGlobalInfo::m_options.client_cfg_file != "") {
        try {
            m_fl.load_client_config_file(CGlobalInfo::m_options.client_cfg_file);
        } catch (const std::runtime_error &e) {
            std::cout << "\n*** " << e.what() << "\n\n";
            exit(-1);
        }
        CGlobalInfo::m_options.preview.set_client_cfg_enable(true);
        m_fl.set_client_config_tuple_gen_info(&tuple_info); // build TBD YAML
        pre_test();

        /* set the ASTF db with the client information */
        db->set_client_cfg_db(&m_fl.m_client_config_info);
    }

    /* verify options */
    try {
        CGlobalInfo::m_options.verify();
    } catch (const std::runtime_error &e) {
        std::cout << "\n*** " << e.what() << "\n\n";
        exit(-1);
    }


    int num_dp_cores = CGlobalInfo::m_options.preview.getCores() * CGlobalInfo::m_options.get_expected_dual_ports();
    CJsonData_err err_obj = db->verify_data(num_dp_cores);

    if (err_obj.is_error()) {
        std::cerr << "Error: " << err_obj.description() << std::endl;
        exit(-1);
    }

    CTcpLatency lat;
    db->get_latency_params(lat);

    if (CGlobalInfo::m_options.preview.get_is_client_cfg_enable()) {

        m_mg.set_ip( lat.get_c_ip() ,
                   lat.get_s_ip(),
                   lat.get_mask(),
                   m_fl.m_client_config_info);
    } else {
        m_mg.set_ip( lat.get_c_ip() ,
                    lat.get_s_ip(),
                    lat.get_mask());
    }

    return (0);
}


COLD_FUNC int CGlobalTRex::start_master_astf() {
    start_master_astf_common();
    return (0);
}


COLD_FUNC int CGlobalTRex::start_master_statefull() {
    int i;
    for (i=0; i<BP_MAX_CORES; i++) {
        m_signal[i]=0;
    }

    m_fl.Create();

    m_fl.load_from_yaml(CGlobalInfo::m_options.cfg_file,get_cores_tx());
    if ( CGlobalInfo::m_options.m_active_flows>0 ) {
        m_fl.update_active_flows(CGlobalInfo::m_options.m_active_flows);
    } else if ( CGlobalInfo::m_options.m_is_lowend ) {
        m_fl.update_active_flows(LOWEND_LIMIT_ACTIVEFLOWS);
    }
    /* client config */
    if (CGlobalInfo::m_options.client_cfg_file != "") {
        try {
            m_fl.load_client_config_file(CGlobalInfo::m_options.client_cfg_file);
        } catch (const std::runtime_error &e) {
            std::cout << "\n*** " << e.what() << "\n\n";
            exit(-1);
        }
        CGlobalInfo::m_options.preview.set_client_cfg_enable(true);
        m_fl.set_client_config_tuple_gen_info(&m_fl.m_yaml_info.m_tuple_gen);
        pre_test();
    }



    /* verify options */
    try {
        CGlobalInfo::m_options.verify();
    } catch (const std::runtime_error &e) {
        std::cout << "\n*** " << e.what() << "\n\n";
        exit(-1);
    }

    float dummy_factor = 1.0 - (float) CGlobalInfo::m_options.m_dummy_count / m_max_ports;
    m_expected_pps = m_fl.get_total_pps() * dummy_factor;
    m_expected_cps = 1000.0 * m_fl.get_total_kcps() * dummy_factor;
    m_expected_bps = m_fl.get_total_tx_bps() * dummy_factor;
    if ( m_fl.get_total_repeat_flows() > 2000) {
        /* disable flows cache */
        CGlobalInfo::m_options.preview.setDisableMbufCache(true);
    }

    CTupleGenYamlInfo * tg=&m_fl.m_yaml_info.m_tuple_gen;


    /* for client cluster configuration - pass the IP start entry */
    if (CGlobalInfo::m_options.preview.get_is_client_cfg_enable()) {

        m_mg.set_ip( tg->m_client_pool[0].get_ip_start(),
                     tg->m_server_pool[0].get_ip_start(),
                     tg->m_client_pool[0].getDualMask(),
                     m_fl.m_client_config_info);
    } else {

        m_mg.set_ip( tg->m_client_pool[0].get_ip_start(),
                     tg->m_server_pool[0].get_ip_start(),
                     tg->m_client_pool[0].getDualMask());
    }


    if (  isVerbose(0) ) {
        m_fl.DumpCsv(stdout);
        for (i=0; i<100; i++) {
            fprintf(stdout,"\n");
        }
        fflush(stdout);
    }

    m_fl.generate_p_thread_info(get_cores_tx());
    CFlowGenListPerThread   * lpt;

    for (i=0; i<get_cores_tx(); i++) {
        lpt = m_fl.m_threads_info[i];
        //CNullIF * erf_vif = new CNullIF();
        CVirtualIF * erf_vif = m_cores_vif[i+1];
        lpt->set_vif(erf_vif);
        lpt->set_sync_barrier(m_sync_barrier);
    }
    m_fl_was_init=true;

    return (0);
}

static void restore_segfault_handler(int signum) {
    struct sigaction action;

    action.sa_handler = SIG_DFL;
    sigemptyset(&action.sa_mask);
    sigaddset(&action.sa_mask, signum);
    sigaction(signum, &action, NULL);
}

/**
 * handle a signal for termination
 *
 * @author imarom (7/27/2016)
 *
 * @param signum
 */
static void trex_termination_handler(int signum) {
    std::stringstream ss;

    /* be sure that this was given on the main process */
    assert(rte_eal_process_type() == RTE_PROC_PRIMARY);

    switch (signum) {
    case SIGINT:
        g_trex.mark_for_shutdown(CGlobalTRex::SHUTDOWN_SIGINT);
        break;

    case SIGTERM:
        g_trex.mark_for_shutdown(CGlobalTRex::SHUTDOWN_SIGTERM);
        break;

    case SIGSEGV:
    case SIGILL:
    case SIGFPE:
        std::string Backtrace(int skip = 1); // @trex_watchdog.cpp

        ss << "Error: signal " << signum << ":";
        ss << "\n\n*** traceback follows ***\n\n" << Backtrace() << "\n";
        std::cout << ss.str() << std::endl;

        restore_segfault_handler(signum);
        break;

    default:
        assert(0);
    }

}

void CGlobalTRex::register_signals() {
    struct sigaction action;

    /* handler */
    action.sa_handler = trex_termination_handler;

    /* blocked signals during handling */
    sigemptyset(&action.sa_mask);
    sigaddset(&action.sa_mask, SIGINT);
    sigaddset(&action.sa_mask, SIGTERM);
    sigaddset(&action.sa_mask, SIGSEGV);
    sigaddset(&action.sa_mask, SIGILL);
    sigaddset(&action.sa_mask, SIGFPE);

    /* no flags */
    action.sa_flags = 0;

    /* register */
    sigaction(SIGINT,  &action, NULL);
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGSEGV, &action, NULL);
    sigaction(SIGILL,  &action, NULL);
    sigaction(SIGFPE,  &action, NULL);
}

COLD_FUNC int CGlobalTRex::run_in_master() {

  // rte_thread_setname(pthread_self(), "TRex Control");

  m_stx->launch_control_plane();

  /* exception and scope safe */
  std::unique_lock<std::recursive_mutex> cp_lock(m_cp_lock);

  uint32_t slow_path_counter = 0;

  const int FASTPATH_DELAY_MS = 10;
  const int SLOWPATH_DELAY_MS = 500;

  m_monitor.create("master", 2);
  TrexWatchDog::getInstance().register_monitor(&m_monitor);

  TrexWatchDog::getInstance().start();

  if ( get_is_interactive() ) {
    apply_pretest_results_to_stack();
    run_bird_with_ns();
  }
  while (!is_marked_for_shutdown()) {

    /* fast path */
    handle_fast_path();

    /* slow path */
    if (slow_path_counter >= SLOWPATH_DELAY_MS) {
      handle_slow_path();
      slow_path_counter = 0;
    }

    m_monitor.disable(30); // assume we will wake up

    cp_lock.unlock();
    if (likely(!m_stx->has_dp_messages())) {
      delay(FASTPATH_DELAY_MS);
      slow_path_counter += FASTPATH_DELAY_MS;
    }
    cp_lock.lock();

    m_monitor.enable();
  }

  /* on exit release the lock */
  cp_lock.unlock();

  /* shutdown everything gracefully */
  shutdown();

  return (0);
}