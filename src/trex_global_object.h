#ifndef __TREX_GLOBAL_OBJECT_H__
#define __TREX_GLOBAL_OBJECT_H__

#include <assert.h>
#include <pthread.h>
#include <signal.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <zmq.h>
#include <rte_config.h>
#include <rte_common.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_tailq.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_random.h>
#include <rte_version.h>
#include <rte_ip.h>
#include <rte_bus_pci.h>

#include "hot_section.h"
#include "stt_cp.h"

#include "bp_sim.h"
#include "os_time.h"
#include "common/arg/SimpleGlob.h"
#include "common/arg/SimpleOpt.h"
#include "common/basic_utils.h"
#include "utl_sync_barrier.h"
#include "trex_build_info.h"

extern "C" {
#include "dpdk/drivers/net/ixgbe/base/ixgbe_type.h"
}

#include "trex_messaging.h"
#include "trex_rx_core.h"

/* stateless */
#include "stl/trex_stl.h"
#include "stl/trex_stl_stream_node.h"

/* stateful */
#include "stf/trex_stf.h"

/* ASTF */
#include "astf/trex_astf.h"
#include "astf_batch/trex_astf_batch.h"

#include "publisher/trex_publisher.h"
#include "../linux_dpdk/version.h"

#include "dpdk_funcs.h"
#include "global_io_mode.h"
#include "utl_term_io.h"
#include "msg_manager.h"
#include "platform_cfg.h"
#include "pre_test.h"
#include "stateful_rx_core.h"
#include "debug.h"
#include "pkt_gen.h"
#include "trex_port_attr.h"
#include "drivers/trex_driver_base.h"
#include "internal_api/trex_platform_api.h"
#include "main_dpdk.h"
#include "trex_watchdog.h"
#include "utl_port_map.h"
#include "astf/astf_db.h"
#include "utl_offloads.h"

#define INVALID_TX_QUEUE_ID 0xffff

class CGlobalTRex  {

public:
    /**
     * different types of shutdown causes
     */
    typedef enum {
        SHUTDOWN_NONE,
        SHUTDOWN_TEST_ENDED,
        SHUTDOWN_CTRL_C,
        SHUTDOWN_SIGINT,
        SHUTDOWN_SIGTERM,
        SHUTDOWN_RPC_REQ,
        SHUTDOWN_NOT_ENOGTH_CLIENTS

    } shutdown_rc_e;

    CGlobalTRex (){
        m_max_ports=4;
        m_max_cores=1;
        m_cores_to_dual_ports=0;
        m_max_queues_per_port=0;
        m_fl_was_init=false;
        m_expected_pps=0.0;
        m_expected_cps=0.0;
        m_expected_bps=0.0;
        m_stx = NULL;
        m_mark_for_shutdown = SHUTDOWN_NONE;
        m_mark_not_enogth_clients =false;
        m_sync_barrier=0;
    }

    bool Create();
    void Delete();
    int  device_prob_init();
    int  cores_prob_init();
    int  queues_prob_init();
    int  device_start();
    int  device_rx_queue_flush();
    void init_vif_cores();
    
    void rx_batch_conf();
    void rx_interactive_conf();
    
    TrexSTXCfg get_stx_cfg();
    
    void init_stl();
    void init_stf();
    void init_astf();

    void init_stl_stats();

    void init_astf_batch();
    
    bool is_all_links_are_up(bool dump=false);
    void pre_test();
    void run_bird_with_ns();
    void apply_pretest_results_to_stack(void);
    void abort_gracefully(const std::string &on_stdout,
                          const std::string &on_publisher) __attribute__ ((__noreturn__));

    /**
     * mark for shutdown
     * on the next check - the control plane will
     * call shutdown()
     */
    void mark_for_shutdown(shutdown_rc_e rc) {

        if (is_marked_for_shutdown()) {
            return;
        }

        m_mark_for_shutdown = rc;
    }

    bool is_marked_for_shutdown() const {
        return (m_mark_for_shutdown != SHUTDOWN_NONE);
    }

private:
    void init_astf_vif_rx_queues();

    void register_signals();

    /* try to stop all datapath cores and RX core */
    void wait_for_all_cores();

    std::string get_shutdown_cause() const {
        switch (m_mark_for_shutdown) {

        case SHUTDOWN_NONE:
            return "";

        case SHUTDOWN_TEST_ENDED:
            return "test has ended";

        case SHUTDOWN_CTRL_C:
            return "CTRL + C detected";

        case SHUTDOWN_SIGINT:
            return "received signal SIGINT";

        case SHUTDOWN_SIGTERM:
            return "received signal SIGTERM";

        case SHUTDOWN_RPC_REQ:
            return "server received RPC 'shutdown' request";

        case SHUTDOWN_NOT_ENOGTH_CLIENTS :
            return "there are not enogth clients for this rate, try to add more";
        default:
            assert(0);
        }

    }


    /**
     * shutdown sequence
     *
     */
    void shutdown();

public:
    int start_master_astf_common();
    int start_master_astf_batch();
    int start_master_astf();

    int start_master_statefull();
    int start_master_stateless();
    int run_in_core(virtual_thread_id_t virt_core_id);
    int run_in_rx_core();
    int run_in_master();

    void handle_fast_path();
    void handle_slow_path();

    int stop_master();
    /* return the minimum number of dp cores needed to support the active ports
       this is for c==1 or  m_cores_mul==1
    */
    int get_base_num_cores(){
        return (m_max_ports>>1);
    }

    int get_cores_tx(){
        /* 0 - master
           num_of_cores -
           last for latency */
        if ( (! get_is_rx_thread_enabled()) ) {
            return (m_max_cores - 1 );
        } else {
            return (m_max_cores - BP_MASTER_AND_LATENCY );
        }
    }

private:
    bool is_all_dp_cores_finished();
    bool is_all_cores_finished();

    void check_for_ports_link_change();
    void check_for_io();
    void show_panel();

public:

    void sync_threads_stats();
    void publish_async_data(bool sync_now, bool baseline = false);
    void publish_async_barrier(uint32_t key);
    void publish_async_port_attr_changed(uint8_t port_id);

    void global_stats_to_json(Json::Value &output);
    void port_stats_to_json(Json::Value &output, uint8_t port_id);

    void dump_stats(FILE *fd,
                    CGlobalStats::DumpFormat format);
    void dump_template_info(std::string & json);
    bool sanity_check();
    void update_stats(void);
    tx_per_flow_t get_flow_tx_stats(uint8_t port, uint16_t hw_id);
    tx_per_flow_t clear_flow_tx_stats(uint8_t port, uint16_t index, bool is_lat);
    void get_stats(CGlobalStats & stats);
    float get_cpu_util_per_interface(uint8_t port_id);
    void dump_post_test_stats(FILE *fd);
    void dump_config(FILE *fd);
    void dump_links_status(FILE *fd);

    bool lookup_port_by_mac(const uint8_t *mac, uint8_t &port_id);

    uint16_t get_rx_core_tx_queue_id();
    uint16_t get_latency_tx_queue_id();

public:
    port_cfg_t  m_port_cfg;
    uint32_t    m_max_ports;    /* active number of ports supported options are  2,4,8,10,12  */
    uint32_t    m_max_cores;    /* current number of cores , include master and latency  ==> ( master)1+c*(m_max_ports>>1)+1( latency )  */
    uint32_t    m_cores_mul;    /* how cores multipler given  c=4 ==> m_cores_mul */
    uint32_t    m_max_queues_per_port; // Number of TX queues per port
    uint32_t    m_cores_to_dual_ports; /* number of TX cores allocated for each port pair */
    uint16_t    m_rx_core_tx_q_id; /* TX q used by rx core */
    // statistic
    CPPSMeasure  m_cps;
    float        m_expected_pps;
    float        m_expected_cps;
    float        m_expected_bps;//bps
    float        m_last_total_cps;

    CPhyEthIF          *m_ports[TREX_MAX_PORTS];
    CCoreEthIF          m_cores_vif_stf[BP_MAX_CORES]; /* counted from 1 , 2,3 core zero is reserved - stateful */
    CCoreEthIFStateless m_cores_vif_stl[BP_MAX_CORES]; /* counted from 1 , 2,3 core zero is reserved - stateless*/
    CCoreEthIFTcp       m_cores_vif_tcp[BP_MAX_CORES];
    CCoreEthIF *        m_cores_vif[BP_MAX_CORES];
    CParserOption       m_po;
    CFlowGenList        m_fl;
    bool                m_fl_was_init;
    CLatencyManager     m_mg; // statefull RX core
    CTrexGlobalIoMode   m_io_modes;
    CTRexExtendedDriverBase * m_drv;

private:
    CLatencyHWPort        m_latency_vports[TREX_MAX_PORTS];    /* read hardware driver */
    CLatencyVmPort        m_latency_vm_vports[TREX_MAX_PORTS]; /* vm driver */
    CLatencyPktInfo       m_latency_pkt;
    TrexPublisher         m_zmq_publisher;
    CGlobalStats          m_stats;
    uint32_t              m_stats_cnt;
    std::recursive_mutex  m_cp_lock;

    TrexMonitor           m_monitor;
    shutdown_rc_e         m_mark_for_shutdown;
    bool                  m_mark_not_enogth_clients;

public:
    TrexSTX              *m_stx;
    CSyncBarrier *        m_sync_barrier;

	/* last */
	volatile uint8_t    m_signal[BP_MAX_CORES] __rte_cache_aligned ; // Signal to main core when DP thread finished
} __rte_cache_aligned;


extern CGlobalTRex g_trex;

#endif /* __TREX_GLOBAL_OBJECT_H__ */
