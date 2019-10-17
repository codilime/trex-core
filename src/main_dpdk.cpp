/*
  Hanoh Haim
  Cisco Systems, Inc.
*/

/*
  Copyright (c) 2015-2017 Cisco Systems, Inc.

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
#include "trex_global_object.h"

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
#include "debug.h"
#include "pkt_gen.h"
#include "trex_port_attr.h"
#include "trex_driver_base.h"
#include "internal_api/trex_platform_api.h"
#include "main_dpdk.h"
#include "trex_watchdog.h"
#include "utl_port_map.h"
#include "astf/astf_db.h"
#include "utl_offloads.h"
#include "internal_api/trex_platform_api_dpdk.h"
#include "trex_global_object.h"

void set_driver();
void reorder_dpdk_ports();


static int g_dpdk_args_num ;
static char * g_dpdk_args[MAX_DPDK_ARGS];
static char g_cores_str[100];
static char g_socket_mem_str[200];
static char g_prefix_str[100];
static char g_loglevel_str[20];
static char g_master_id_str[10];
static char g_image_postfix[10];

CTRexExtendedDriverDb * CTRexExtendedDriverDb::m_ins;
CPlatformYamlInfo global_platform_cfg_info;
CPciPorts port_map;

static inline int get_min_sample_rate(void){
    return ( get_ex_drv()->get_min_sample_rate());
}

// cores =0==1,1*2,2,3,4,5,6
// An enum for all the option types
enum { 
       /* no more before this */
       OPT_MIN,

       OPT_HELP,
       OPT_MODE_BATCH,
       OPT_MODE_INTERACTIVE,
       OPT_NODE_DUMP,
       OPT_DUMP_INTERFACES,
       OPT_UT,
       OPT_PROM, 
       OPT_CORES,
       OPT_SINGLE_CORE,
       OPT_FLIP_CLIENT_SERVER,
       OPT_FLOW_FLIP_CLIENT_SERVER,
       OPT_FLOW_FLIP_CLIENT_SERVER_SIDE,
       OPT_RATE_MULT,
       OPT_DURATION,
       OPT_PLATFORM_FACTOR,
       OPT_PUB_DISABLE,
       OPT_LIMT_NUM_OF_PORTS,
       OPT_PLAT_CFG_FILE,
       OPT_MBUF_FACTOR,
       OPT_LATENCY,
       OPT_NO_CLEAN_FLOW_CLOSE,
       OPT_LATENCY_MASK,
       OPT_ONLY_LATENCY,
       OPT_LATENCY_PREVIEW ,
       OPT_WAIT_BEFORE_TRAFFIC,
       OPT_PCAP,
       OPT_RX_CHECK,
       OPT_IO_MODE,
       OPT_IPV6,
       OPT_LEARN,
       OPT_LEARN_MODE,
       OPT_LEARN_VERIFY,
       OPT_L_PKT_MODE,
       OPT_NO_FLOW_CONTROL,
       OPT_NO_HW_FLOW_STAT,
       OPT_X710_RESET_THRESHOLD,
       OPT_VLAN,
       OPT_RX_CHECK_HOPS,
       OPT_CLIENT_CFG_FILE,
       OPT_NO_KEYBOARD_INPUT,
       OPT_VIRT_ONE_TX_RX_QUEUE,
       OPT_PREFIX,
       OPT_RPC_LOGFILE,
       OPT_SEND_DEBUG_PKT,
       OPT_NO_WATCHDOG,
       OPT_ALLOW_COREDUMP,
       OPT_CHECKSUM_OFFLOAD,
       OPT_CHECKSUM_OFFLOAD_DISABLE,
       OPT_TSO_OFFLOAD_DISABLE,
       OPT_LRO_OFFLOAD_DISABLE,
       OPT_CLOSE,
       OPT_ARP_REF_PER,
       OPT_NO_OFED_CHECK,
       OPT_NO_SCAPY_SERVER,
       OPT_SCAPY_SERVER,
       OPT_BIRD_SERVER,
       OPT_ACTIVE_FLOW,
       OPT_RT,
       OPT_TCP_MODE,
       OPT_STL_MODE,
       OPT_MLX4_SO,
       OPT_MLX5_SO,
       OPT_NTACC_SO,
       OPT_ASTF_SERVR_ONLY,
       OPT_ASTF_CLIENT_MASK,
       OPT_ASTF_TUNABLE,
       OPT_NO_TERMIO,
       OPT_QUEUE_DROP,
       OPT_ASTF_EMUL_DEBUG, 
       OPT_SLEEPY_SCHEDULER,
       OPT_UNBIND_UNUSED_PORTS,
       OPT_HDRH,
    
       /* no more pass this */
       OPT_MAX

};

/* options hash - for first pass */
using OptHash = std::unordered_map<int, bool>;

/* these are the argument types:
   SO_NONE --    no argument needed
   SO_REQ_SEP -- single required argument
   SO_MULTI --   multiple arguments needed
*/
static CSimpleOpt::SOption parser_options[] =
    {
        { OPT_HELP,                   "-?",                SO_NONE    },
        { OPT_HELP,                   "-h",                SO_NONE    },
        { OPT_HELP,                   "--help",            SO_NONE    },
        { OPT_UT,                     "--ut",              SO_NONE    },
        { OPT_MODE_BATCH,             "-f",                SO_REQ_SEP },
        { OPT_PROM,                   "--prom",            SO_NONE },
        { OPT_MODE_INTERACTIVE,       "-i",                SO_NONE    },
        { OPT_PLAT_CFG_FILE,          "--cfg",             SO_REQ_SEP },
        { OPT_SINGLE_CORE,            "-s",                SO_NONE    },
        { OPT_FLIP_CLIENT_SERVER,     "--flip",            SO_NONE    },
        { OPT_FLOW_FLIP_CLIENT_SERVER,"-p",                SO_NONE    },
        { OPT_FLOW_FLIP_CLIENT_SERVER_SIDE, "-e",          SO_NONE    },
        { OPT_NO_CLEAN_FLOW_CLOSE,    "--nc",              SO_NONE    },
        { OPT_LIMT_NUM_OF_PORTS,      "--limit-ports",     SO_REQ_SEP },
        { OPT_CORES,                  "-c",                SO_REQ_SEP },
        { OPT_NODE_DUMP,              "-v",                SO_REQ_SEP },
        { OPT_DUMP_INTERFACES,        "--dump-interfaces", SO_MULTI   },
        { OPT_LATENCY,                "-l",                SO_REQ_SEP },
        { OPT_DURATION,               "-d",                SO_REQ_SEP },
        { OPT_PLATFORM_FACTOR,        "-pm",               SO_REQ_SEP },
        { OPT_PUB_DISABLE,            "-pubd",             SO_NONE    },
        { OPT_RATE_MULT,              "-m",                SO_REQ_SEP },
        { OPT_LATENCY_MASK,           "--lm",              SO_REQ_SEP },
        { OPT_ONLY_LATENCY,           "--lo",              SO_NONE    },
        { OPT_LATENCY_PREVIEW,        "-k",                SO_REQ_SEP },
        { OPT_WAIT_BEFORE_TRAFFIC,    "-w",                SO_REQ_SEP },
        { OPT_PCAP,                   "--pcap",            SO_NONE    },
        { OPT_RX_CHECK,               "--rx-check",        SO_REQ_SEP },
        { OPT_IO_MODE,                "--iom",             SO_REQ_SEP },
        { OPT_RX_CHECK_HOPS,          "--hops",            SO_REQ_SEP },
        { OPT_IPV6,                   "--ipv6",            SO_NONE    },
        { OPT_LEARN,                  "--learn",           SO_NONE    },
        { OPT_LEARN_MODE,             "--learn-mode",      SO_REQ_SEP },
        { OPT_LEARN_VERIFY,           "--learn-verify",    SO_NONE    },
        { OPT_L_PKT_MODE,             "--l-pkt-mode",      SO_REQ_SEP },
        { OPT_NO_FLOW_CONTROL,        "--no-flow-control-change", SO_NONE },
        { OPT_NO_HW_FLOW_STAT,        "--no-hw-flow-stat", SO_NONE },
        { OPT_X710_RESET_THRESHOLD,   "--x710-reset-threshold", SO_REQ_SEP },
        { OPT_VLAN,                   "--vlan",            SO_NONE    },
        { OPT_CLIENT_CFG_FILE,        "--client_cfg",      SO_REQ_SEP },
        { OPT_CLIENT_CFG_FILE,        "--client-cfg",      SO_REQ_SEP },
        { OPT_NO_KEYBOARD_INPUT,      "--no-key",          SO_NONE    },
        { OPT_VIRT_ONE_TX_RX_QUEUE,   "--software",        SO_NONE    },
        { OPT_PREFIX,                 "--prefix",          SO_REQ_SEP },
        { OPT_RPC_LOGFILE,            "--rpc-logfile",     SO_REQ_SEP },
        { OPT_SEND_DEBUG_PKT,         "--send-debug-pkt",  SO_REQ_SEP },
        { OPT_MBUF_FACTOR,            "--mbuf-factor",     SO_REQ_SEP },
        { OPT_NO_WATCHDOG,            "--no-watchdog",     SO_NONE    },
        { OPT_ALLOW_COREDUMP,         "--allow-coredump",  SO_NONE    },
        { OPT_CHECKSUM_OFFLOAD,       "--checksum-offload", SO_NONE   },
        { OPT_CHECKSUM_OFFLOAD_DISABLE, "--checksum-offload-disable", SO_NONE   },
        { OPT_TSO_OFFLOAD_DISABLE,  "--tso-disable", SO_NONE   },
        { OPT_LRO_OFFLOAD_DISABLE,  "--lro-disable", SO_NONE   },
        { OPT_ACTIVE_FLOW,            "--active-flows",   SO_REQ_SEP  },
        { OPT_NTACC_SO,               "--ntacc-so", SO_NONE    },
        { OPT_MLX5_SO,                "--mlx5-so", SO_NONE    },
        { OPT_MLX4_SO,                "--mlx4-so", SO_NONE    },
        { OPT_CLOSE,                  "--close-at-end",    SO_NONE    },
        { OPT_ARP_REF_PER,            "--arp-refresh-period", SO_REQ_SEP },
        { OPT_NO_OFED_CHECK,          "--no-ofed-check",    SO_NONE    },
        { OPT_NO_SCAPY_SERVER,        "--no-scapy-server",  SO_NONE    },
        { OPT_SCAPY_SERVER,           "--scapy-server",     SO_NONE    },
        { OPT_BIRD_SERVER,            "--bird-server",      SO_NONE    },
        { OPT_UNBIND_UNUSED_PORTS,    "--unbind-unused-ports", SO_NONE    },
        { OPT_HDRH,                   "--hdrh", SO_NONE    },
        { OPT_RT,                     "--rt",              SO_NONE    },
        { OPT_TCP_MODE,               "--astf",            SO_NONE},
        { OPT_ASTF_EMUL_DEBUG,        "--astf-emul-debug",  SO_NONE},
        { OPT_STL_MODE,               "--stl",             SO_NONE},
        { OPT_ASTF_SERVR_ONLY,        "--astf-server-only",            SO_NONE},
        { OPT_ASTF_CLIENT_MASK,       "--astf-client-mask",SO_REQ_SEP},
        { OPT_ASTF_TUNABLE,           "-t",                SO_REQ_SEP},
        { OPT_NO_TERMIO,              "--no-termio",       SO_NONE},
        { OPT_QUEUE_DROP,             "--queue-drop",      SO_NONE},
        { OPT_SLEEPY_SCHEDULER,       "--sleeps",          SO_NONE},

        SO_END_OF_OPTIONS
    };

static int COLD_FUNC  usage() {

    printf(" Usage: t-rex-64 [mode] <options>\n\n");
    printf(" mode is one of:\n");
    printf("   -f <file> : YAML file with traffic template configuration (Will run TRex in 'stateful' mode)\n");
    printf("   -i        : Run TRex in 'stateless' mode\n");
    printf("\n");

    printf(" Available options are:\n");
    printf(" --astf                     : Enable advanced stateful mode. profile should be in py format and not YAML format \n");
    printf(" --astf-server-only         : Only server  side ports (1,3..) are enabled with ASTF service. Traffic won't be transmitted on clients ports. \n");
    printf(" --astf-client-mask         : Enable only specific client side ports with ASTF service. \n");
    printf("                              For example, with 4 ports setup. 0x1 means that only port 0 will be enabled. ports 2 won't be enabled. \n");
    printf("                              Can't be used with --astf-server-only. \n");
    printf("\n");
    printf(" --stl                      : Starts in stateless mode. must be provided along with '-i' for interactive mode \n");
    printf(" --active-flows             : An experimental switch to scale up or down the number of active flows.  \n");
    printf("                              It is not accurate due to the quantization of flow scheduler and in some case does not work. \n");
    printf("                              Example --active-flows 500000 wil set the ballpark of the active flow to be ~0.5M \n");
    printf(" --allow-coredump           : Allow creation of core dump \n");
    printf(" --arp-refresh-period       : Period in seconds between sending of gratuitous ARP for our addresses. Value of 0 means 'never send' \n");
    printf(" -c <num>>                  : Number of hardware threads to allocate for each port pair. Overrides the 'c' argument from config file \n");
    printf(" --cfg <file>               : Use file as TRex config file instead of the default /etc/trex_cfg.yaml \n");
    printf(" --checksum-offload         : Deprecated,enable by default. Enable IP, TCP and UDP tx checksum offloading, using DPDK. This requires all used interfaces to support this  \n");
    printf(" --checksum-offload-disable : Disable IP, TCP and UDP tx checksum offloading, using DPDK. This requires all used interfaces to support this  \n");
    printf(" --tso-disable              : disable TSO (advanced TCP mode) \n");
    printf(" --lro-disable              : disable LRO (advanced TCP mode) \n");
    printf(" --client-cfg <file>        : YAML file describing clients configuration \n");
    printf(" --close-at-end             : Call rte_eth_dev_stop and close at exit. Calling these functions caused link down issues in older versions, \n");
    printf("                               so we do not call them by default for now. Leaving this as option in case someone thinks it is helpful for him \n");
    printf("                               This it temporary option. Will be removed in the future \n");
    printf(" -d                         : Duration of the test in sec (default is 3600). Look also at --nc \n");
    printf(" -e                         : Like -p but src/dst IP will be chosen according to the port (i.e. on client port send all packets with client src and server dest, and vice versa on server port \n");
    printf(" --flip                     : Each flow will be sent both from client to server and server to client. This can achieve better port utilization when flow traffic is asymmetric \n");
    printf(" --hdrh                     : Report latency using high dynamic range histograms (http://hdrhistogram.org)\n");
    printf(" --hops <hops>              : If rx check is enabled, the hop number can be assigned. See manual for details \n");
    printf(" --iom  <mode>              : IO mode  for server output [0- silent, 1- normal , 2- short] \n");
    printf(" --ipv6                     : Work in ipv6 mode \n");
    printf(" -k  <num>                  : Run 'warm up' traffic for num seconds before starting the test.\n");
    printf("                               Works only with the latency test (-l option)\n");
    printf(" -l <rate>                  : In parallel to the test, run latency check, sending packets at rate/sec from each interface \n");
    printf(" --l-pkt-mode <0-3>         : Set mode for sending latency packets \n");
    printf("      0 (default)    send SCTP packets  \n");
    printf("      1              Send ICMP request packets  \n");
    printf("      2              Send ICMP requests from client side, and response from server side (for working with firewall) \n");
    printf("      3              Send ICMP requests with sequence ID 0 from both sides \n");
    printf("    Rate of zero means no latency check \n");
    printf(" --learn (deprecated). Replaced by --learn-mode. To get older behaviour, use --learn-mode 2 \n");
    printf(" --learn-mode [1-3]         : Used for working in NAT environments. Dynamically learn the NAT translation done by the DUT \n");
    printf("      1    In case of TCP flow, use TCP ACK in first SYN to pass NAT translation information. Initial SYN packet must be first packet in the TCP flow \n");
    printf("           In case of UDP stream, NAT translation information will pass in IP ID field of first packet in flow. This means that this field is changed by TRex\n");
    printf("      2    Add special IP option to pass NAT translation information to first packet of each flow. Will not work on certain firewalls if they drop packets with IP options \n");
    printf("      3    Like 1, but without support for sequence number randomization in server->client direction. Performance (flow/second) better than 1 \n");
    printf(" --learn-verify             : Test the NAT translation mechanism. Should be used when there is no NAT in the setup \n");
    printf(" --limit-ports              : Limit number of ports used. Must be even number (TRex always uses port pairs) \n");
    printf(" --lm                       : Hex mask of cores that should send traffic \n");
    printf("                              For example: Value of 0x5 will cause only ports 0 and 2 to send traffic \n");
    printf(" --lo                       : Only run latency test \n");
    printf(" -m <num>                   : Rate multiplier.  Multiply basic rate of templates by this number \n");
    printf(" --mbuf-factor              : Factor for packet memory \n");
    printf(" --nc                       : If set, will not wait for all flows to be closed, before terminating - see manual for more information \n");
    printf(" --no-flow-control-change   : By default TRex disables flow-control. If this option is given, it does not touch it \n");
    printf(" --no-hw-flow-stat          : Relevant only for Intel x710 stateless mode. Do not use HW counters for flow stats\n");
    printf("                            : Enabling this will support lower traffic rate, but will also report RX byte count statistics. See manual for more details\n");
    printf(" --no-key                   : Daemon mode, don't get input from keyboard \n");
    printf(" --no-ofed-check            : Disable the check of OFED version \n");
    printf(" --no-scapy-server          : Disable Scapy server implicit start at stateless \n");
    printf(" --scapy-server             : Enable Scapy server implicit start at ASTF \n");
    printf(" --no-termio                : Do not use TERMIO. useful when using GDB and ctrl+c is needed. \n");
    printf(" --no-watchdog              : Disable watchdog \n");
    printf(" --rt                       : Run TRex DP/RX cores in realtime priority \n");
    printf(" -p                         : Send all flow packets from the same interface (choosed randomly between client ad server ports) without changing their src/dst IP \n");
    printf(" -pm                        : Platform factor. If you have splitter in the setup, you can multiply the total results by this factor \n");
    printf("                              e.g --pm 2.0 will multiply all the results bps in this factor \n");
    printf(" --prefix <nam>             : For running multi TRex instances on the same machine. Each instance should have different name \n");
    printf(" --prom                     : Enable promiscuous for ASTF/STF mode  \n");
    printf(" -pubd                      : Disable monitors publishers \n");
    printf(" --queue-drop               : Do not retry to send packets on failure (queue full etc.)\n");
    printf(" --rpc-log <file>           : Save log of RPC conversation in logfile\n");
    printf(" --rx-check  <rate>         : Enable rx check. TRex will sample flows at 1/rate and check order, latency and more \n");
    printf(" -s                         : Single core. Run only one data path core. For debug \n");
    printf(" --send-debug-pkt <proto>   : Do not run traffic generator. Just send debug packet and dump receive queues \n");
    printf("                              Supported protocols are 1 for icmp, 2 for UDP, 3 for TCP, 4 for ARP, 5 for 9K UDP \n");
    printf(" --sleeps                   : Use sleeps instead of busy wait in scheduler (less accurate, more power saving)\n");
    printf(" --software                 : Do not configure any hardware rules. In this mode we use 1 core, and one RX queue and one TX queue per port\n");
    printf(" --unbind-unused-ports      : Automatically unbind all unused bound ports in same NIC instead of exiting with error (i40e only)\n");
    printf(" -v <verbosity level>       : The higher the value, print more debug information \n");
    printf(" --vlan                     : Relevant only for stateless mode with Intel 82599 10G NIC \n");
    printf("                              When configuring flow stat and latency per stream rules, assume all streams uses VLAN \n");
    printf(" -w  <num>                  : Wait num seconds between init of interfaces and sending traffic, default is 1 \n");
    

    printf("\n");
    printf(" Examples: ");
    printf(" basic trex run for 20 sec and multiplier of 10 \n");
    printf("  t-rex-64 -f cap2/dns.yaml -m 10 -d 20 \n");
    printf("\n\n");
    printf(" Copyright (c) 2015-2017 Cisco Systems, Inc.    \n");
    printf("                                                                  \n");
    printf(" Licensed under the Apache License, Version 2.0 (the 'License') \n");
    printf(" you may not use this file except in compliance with the License. \n");
    printf(" You may obtain a copy of the License at                          \n");
    printf("                                                                  \n");
    printf("    http://www.apache.org/licenses/LICENSE-2.0                    \n");
    printf("                                                                  \n");
    printf(" Unless required by applicable law or agreed to in writing, software \n");
    printf(" distributed under the License is distributed on an \"AS IS\" BASIS,   \n");
    printf(" WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. \n");
    printf(" See the License for the specific language governing permissions and      \n");
    printf(" limitations under the License.                                           \n");
    printf(" \n");
    printf(" Open Source Components / Libraries \n");
    printf(" DPDK       (BSD)       \n");
    printf(" YAML-CPP   (BSD)       \n");
    printf(" JSONCPP    (MIT)       \n");
    printf(" BPF        (BSD)       \n");
    printf(" HDR-HISTOGRAM-C (CC0)  \n");
    printf(" \n");
    printf(" Open Source Binaries \n");
    printf(" ZMQ        (LGPL v3plus) \n");
    printf(" \n");
    printf(" Version : %s   \n",VERSION_BUILD_NUM);
    printf(" DPDK version : %s   \n",rte_version());
    printf(" User    : %s   \n",VERSION_USER);
    printf(" Date    : %s , %s \n",get_build_date(),get_build_time());
    printf(" Uuid    : %s    \n",VERSION_UIID);
    printf(" Git SHA : %s    \n",VERSION_GIT_SHA);
    
    TrexBuildInfo::show();
    
    return (0);
}


int gtest_main(int argc, char **argv) ;

static void parse_err(const std::string &msg) {
    std::cout << "\nArgument Parsing Error: \n\n" << "*** "<< msg << "\n\n";
    exit(-1);
}

/**
 * convert an option to string
 * 
 */
static std::string opt_to_str(int opt) {
    for (const CSimpleOpt::SOption &x : parser_options) {
        if (x.nId == opt) {
            return std::string(x.pszArg);
        }
    }
    
    assert(0);
    return "";
}


/**
 * checks options exclusivity
 * 
 */
static void check_exclusive(const OptHash &args_set,
                            const std::initializer_list<int> &opts,
                            bool at_least_one = false) {
    int seen = -1;
    
    for (int x : opts) {
        if (args_set.at(x)) {
            if (seen == -1) {
                seen = x;
            } else {
                parse_err("'" + opt_to_str(seen) + "' and '" + opt_to_str(x) + "' are mutual exclusive");
            }
        }
    }
    
    if ( (seen == -1) && at_least_one ) {
        std::string opts_str;
        for (int x : opts) {
            opts_str += "'" + opt_to_str(x) + "', ";
        }
        
        /* remove the last 2 chars */
        opts_str.pop_back();
        opts_str.pop_back();
        parse_err("please specify at least one from the following parameters: " + opts_str);
    }
}

struct ParsingOptException : public std::exception {
    const ESOError m_err_code;
    const char    *m_opt_text;
    ParsingOptException(CSimpleOpt &args):
                    m_err_code(args.LastError()),
                    m_opt_text(args.OptionText()) {}
};

static OptHash
args_first_pass(int argc, char *argv[], CParserOption* po) {
    CSimpleOpt args(argc, argv, parser_options);
    OptHash args_set;
    
    /* clear */
    for (int i = OPT_MIN + 1; i < OPT_MAX; i++) {
        args_set[i] = false;
    }
    
    /* set */
    while (args.Next()) {
        if (args.LastError() != SO_SUCCESS) {
            throw ParsingOptException(args);
        }
        args_set[args.OptionId()] = true;
    }
    
    if (args_set[OPT_HELP]) {
        usage();
        exit(0);
    }
    
    /* sanity */
    
    /* STL and TCP */
    check_exclusive(args_set, {OPT_STL_MODE, OPT_TCP_MODE});
    
    /* interactive, batch or dump */
    check_exclusive(args_set, {OPT_MODE_INTERACTIVE, OPT_MODE_BATCH, OPT_DUMP_INTERFACES}, true);
    
    /* interactive mutual exclusion options */
    check_exclusive(args_set, {OPT_MODE_INTERACTIVE, OPT_DURATION});
    check_exclusive(args_set, {OPT_MODE_INTERACTIVE, OPT_CLIENT_CFG_FILE});
    check_exclusive(args_set, {OPT_MODE_INTERACTIVE, OPT_RX_CHECK});
    check_exclusive(args_set, {OPT_MODE_INTERACTIVE, OPT_LATENCY});
    check_exclusive(args_set, {OPT_MODE_INTERACTIVE, OPT_ONLY_LATENCY});
    check_exclusive(args_set, {OPT_MODE_INTERACTIVE, OPT_SINGLE_CORE});
    check_exclusive(args_set, {OPT_MODE_INTERACTIVE, OPT_RATE_MULT});
    
    return args_set;
}

COLD_FUNC void get_dpdk_drv_params(CTrexDpdkParams &dpdk_p){
    CPlatformYamlInfo *cg = &global_platform_cfg_info;

    CTrexDpdkParamsOverride dpdk_over_p;

    get_mode()->get_dpdk_drv_params(dpdk_p);

    /* override by driver */
    if (get_ex_drv()->is_override_dpdk_params(dpdk_over_p)){
        /* need to override by driver */
        if (dpdk_over_p.rx_desc_num_data_q){
            dpdk_p.rx_desc_num_data_q = dpdk_over_p.rx_desc_num_data_q;
        }
        if (dpdk_over_p.rx_desc_num_drop_q){
            dpdk_p.rx_desc_num_drop_q = dpdk_over_p.rx_desc_num_drop_q;
        }
        if (dpdk_over_p.rx_desc_num_dp_q){
            dpdk_p.rx_desc_num_dp_q = dpdk_over_p.rx_desc_num_dp_q;
        }
        if (dpdk_over_p.tx_desc_num){
            dpdk_p.tx_desc_num = dpdk_over_p.tx_desc_num;
        }
    }
    /* override by configuration */
    if (cg->m_rx_desc){
        dpdk_p.rx_desc_num_data_q = cg->m_rx_desc;
        dpdk_p.rx_desc_num_dp_q = cg->m_rx_desc;
    }
    if (cg->m_tx_desc){
        dpdk_p.tx_desc_num = cg->m_tx_desc;
    }


    bool rx_scatter = get_ex_drv()->is_support_for_rx_scatter_gather();
    if (!rx_scatter){
        dpdk_p.rx_mbuf_type = MBUF_9k;
    }
}

COLD_FUNC static int parse_options(int argc, char *argv[], bool first_time ) {
    CSimpleOpt args(argc, argv, parser_options);

    CParserOption *po = &CGlobalInfo::m_options;
    CPlatformYamlInfo *cg = &global_platform_cfg_info;

    bool latency_was_set=false;
    (void)latency_was_set;
    char ** rgpszArg = NULL;
    bool opt_vlan_was_set = false;

    int a=0;
    int node_dump=0;

    po->preview.setFileWrite(true);
    po->preview.setRealTime(true);
    uint32_t tmp_data;
    float tmp_double;
    
    /* first run - pass all parameters for existance */
    OptHash args_set = args_first_pass(argc, argv, po);
    
    
    while ( args.Next() ){
        if (args.LastError() == SO_SUCCESS) {
            switch (args.OptionId()) {

            case OPT_UT :
                parse_err("Supported only in simulation");
                break;

            case OPT_HELP:
                usage();
                return -1;

            case OPT_ASTF_EMUL_DEBUG:
                po->preview.setEmulDebug(true);
                break;
            /* astf */
            case OPT_TCP_MODE:
                /* can be batch or non batch */
                set_op_mode((args_set[OPT_MODE_INTERACTIVE] ? OP_MODE_ASTF : OP_MODE_ASTF_BATCH));
                break;
                
            /* stl */
            case OPT_STL_MODE:
                set_op_mode(OP_MODE_STL);
                break;

            case OPT_ASTF_SERVR_ONLY:
                po->m_astf_mode = CParserOption::OP_ASTF_MODE_SERVR_ONLY;
                break;
            case OPT_ASTF_TUNABLE:
                /* do bothing with it */
                break;
            case OPT_ASTF_CLIENT_MASK:
                po->m_astf_mode = CParserOption::OP_ASTF_MODE_CLIENT_MASK;
                sscanf(args.OptionArg(),"%x", &po->m_astf_client_mask);
                break;

            case OPT_MODE_BATCH:
                po->cfg_file = args.OptionArg();
                break;

            case OPT_PROM :
                po->preview.setPromMode(true);
                break;

            case OPT_MODE_INTERACTIVE:
                /* defines the OP mode */
                break;

            case OPT_NO_KEYBOARD_INPUT  :
                po->preview.set_no_keyboard(true);
                break;

            case OPT_CLIENT_CFG_FILE :
                po->client_cfg_file = args.OptionArg();
                break;

            case OPT_PLAT_CFG_FILE :
                po->platform_cfg_file = args.OptionArg();
                break;

            case OPT_SINGLE_CORE :
                po->preview.setSingleCore(true);
                break;

            case OPT_IPV6:
                po->preview.set_ipv6_mode_enable(true);
                break;

            case OPT_RT:
                po->preview.set_rt_prio_mode(true);
                break;

            case OPT_NTACC_SO:
                po->preview.set_ntacc_so_mode(true);
                break;

            case OPT_MLX5_SO:
                po->preview.set_mlx5_so_mode(true);
                break;

            case OPT_MLX4_SO:
                po->preview.set_mlx4_so_mode(true);
                break;

            case OPT_LEARN :
                po->m_learn_mode = CParserOption::LEARN_MODE_IP_OPTION;
                break;

            case OPT_LEARN_MODE :
                sscanf(args.OptionArg(),"%d", &tmp_data);
                if (! po->is_valid_opt_val(tmp_data, CParserOption::LEARN_MODE_DISABLED, CParserOption::LEARN_MODE_MAX, "--learn-mode")) {
                    exit(-1);
                }
                po->m_learn_mode = (uint8_t)tmp_data;
                break;

            case OPT_LEARN_VERIFY :
                // must configure learn_mode for learn verify to work. If different learn mode will be given later, it will be set instead.
                if (po->m_learn_mode == 0) {
                    po->m_learn_mode = CParserOption::LEARN_MODE_IP_OPTION;
                }
                po->preview.set_learn_and_verify_mode_enable(true);
                break;

            case OPT_L_PKT_MODE :
                sscanf(args.OptionArg(),"%d", &tmp_data);
                if (! po->is_valid_opt_val(tmp_data, 0, L_PKT_SUBMODE_0_SEQ, "--l-pkt-mode")) {
                    exit(-1);
                }
                po->m_l_pkt_mode=(uint8_t)tmp_data;
                break;

            case OPT_NO_HW_FLOW_STAT:
                po->preview.set_disable_hw_flow_stat(true);
                break;
            case OPT_NO_FLOW_CONTROL:
                po->preview.set_disable_flow_control_setting(true);
                break;
            case OPT_X710_RESET_THRESHOLD:
                po->set_x710_fdir_reset_threshold(atoi(args.OptionArg()));
                break;
            case OPT_VLAN:
                opt_vlan_was_set = true;
                break;
            case OPT_LIMT_NUM_OF_PORTS :
                po->m_expected_portd =atoi(args.OptionArg());
                break;
            case  OPT_CORES  :
                po->preview.setCores(atoi(args.OptionArg()));
                break;
            case OPT_FLIP_CLIENT_SERVER :
                po->preview.setClientServerFlip(true);
                break;
            case OPT_NO_CLEAN_FLOW_CLOSE :
                po->preview.setNoCleanFlowClose(true);
                break;
            case OPT_FLOW_FLIP_CLIENT_SERVER :
                po->preview.setClientServerFlowFlip(true);
                break;
            case OPT_FLOW_FLIP_CLIENT_SERVER_SIDE:
                po->preview.setClientServerFlowFlipAddr(true);
                break;
            case OPT_NODE_DUMP:
                a=atoi(args.OptionArg());
                node_dump=1;
                po->preview.setFileWrite(false);
                break;
            case OPT_DUMP_INTERFACES:
                if ( !first_time ) {
                    rgpszArg = args.MultiArg(1);
                    if ( rgpszArg != NULL ) {
                        cg->m_if_list.clear();
                        do {
                            cg->m_if_list.push_back(rgpszArg[0]);
                            rgpszArg = args.MultiArg(1);
                        } while (rgpszArg != NULL);
                    }
                }
                set_op_mode(OP_MODE_DUMP_INTERFACES);
                break;
            case OPT_MBUF_FACTOR:
                sscanf(args.OptionArg(),"%f", &po->m_mbuf_factor);
                break;
            case OPT_RATE_MULT :
                sscanf(args.OptionArg(),"%f", &po->m_factor);
                break;
            case OPT_DURATION :
                sscanf(args.OptionArg(),"%f", &po->m_duration);
                break;
            case OPT_PUB_DISABLE:
                po->preview.set_zmq_publish_enable(false);
                break;
            case OPT_PLATFORM_FACTOR:
                sscanf(args.OptionArg(),"%f", &po->m_platform_factor);
                break;
            case OPT_LATENCY :
                latency_was_set=true;
                sscanf(args.OptionArg(),"%d", &po->m_latency_rate);
                break;
            case OPT_LATENCY_MASK :
                sscanf(args.OptionArg(),"%x", &po->m_latency_mask);
                break;
            case OPT_ONLY_LATENCY :
                po->preview.setOnlyLatency(true);
                break;
            case OPT_NO_TERMIO:
                po->preview.set_termio_disabled(true);
                break;
            case OPT_NO_WATCHDOG :
                po->preview.setWDDisable(true);
                break;
            case OPT_ALLOW_COREDUMP :
                po->preview.setCoreDumpEnable(true);
                break;
            case  OPT_LATENCY_PREVIEW :
                sscanf(args.OptionArg(),"%d", &po->m_latency_prev);
                break;
            case  OPT_WAIT_BEFORE_TRAFFIC :
                sscanf(args.OptionArg(),"%d", &po->m_wait_before_traffic);
                break;
            case OPT_PCAP:
                po->preview.set_pcap_mode_enable(true);
                break;
            case OPT_ACTIVE_FLOW:
                sscanf(args.OptionArg(),"%f", &tmp_double);
                po->m_active_flows=(uint32_t)tmp_double;
                break;
            case OPT_RX_CHECK :
                sscanf(args.OptionArg(),"%d", &tmp_data);
                po->m_rx_check_sample=(uint16_t)tmp_data;
                po->preview.set_rx_check_enable(true);
                break;
            case OPT_RX_CHECK_HOPS :
                sscanf(args.OptionArg(),"%d", &tmp_data);
                po->m_rx_check_hops = (uint16_t)tmp_data;
                break;
            case OPT_IO_MODE :
                sscanf(args.OptionArg(),"%d", &tmp_data);
                po->m_io_mode=(uint16_t)tmp_data;
                break;

            case OPT_VIRT_ONE_TX_RX_QUEUE:
                get_mode()->force_software_mode(true);
                break;

            case OPT_PREFIX:
                po->prefix = args.OptionArg();
                break;

            case OPT_RPC_LOGFILE:
                po->rpc_logfile_name = args.OptionArg();
                break;

            case OPT_SEND_DEBUG_PKT:
                sscanf(args.OptionArg(),"%d", &tmp_data);
                po->m_debug_pkt_proto = (uint8_t)tmp_data;
                break;

            case OPT_CHECKSUM_OFFLOAD:
                po->preview.setChecksumOffloadEnable(true);
                break;

            case OPT_CHECKSUM_OFFLOAD_DISABLE:
                po->preview.setChecksumOffloadDisable(true);
                break;

            case OPT_TSO_OFFLOAD_DISABLE:
                po->preview.setTsoOffloadDisable(true);
                break;
            case OPT_LRO_OFFLOAD_DISABLE:
                po->preview.setLroOffloadDisable(true);
                break;
            case OPT_CLOSE:
                po->preview.setCloseEnable(true);
                break;
            case  OPT_ARP_REF_PER:
                sscanf(args.OptionArg(),"%d", &tmp_data);
                po->m_arp_ref_per=(uint16_t)tmp_data;
                break;
            case OPT_NO_OFED_CHECK:
                break;
            case OPT_NO_SCAPY_SERVER:
                break;
            case OPT_UNBIND_UNUSED_PORTS:
                break;
            case OPT_HDRH:
                po->m_hdrh = true;
                break;
            case OPT_SCAPY_SERVER:
                break;
            case OPT_BIRD_SERVER:
                po->m_is_bird_enabled = true;
                break;
            case OPT_QUEUE_DROP:
                CGlobalInfo::m_options.m_is_queuefull_retry = false;
                break;
            case OPT_SLEEPY_SCHEDULER:
                CGlobalInfo::m_options.m_is_sleepy_scheduler = true;
                break;

            default:
                printf("Error: option %s is not handled.\n\n", args.OptionText());
                return -1;
                break;
            } // End of switch
        }// End of IF
        else {
            throw ParsingOptException(args);
        }
    } // End of while


    /* if no specific mode was provided, fall back to defaults - stateless on intearactive, stateful on batch */
    if (get_op_mode() == OP_MODE_INVALID) {
        set_op_mode( (args_set.at(OPT_MODE_INTERACTIVE)) ? OP_MODE_STL : OP_MODE_STF);
    }

    if ( CGlobalInfo::m_options.m_is_lowend ) {
        po->preview.setCores(1);
    }

    if (CGlobalInfo::is_learn_mode() && po->preview.get_ipv6_mode_enable()) {
        parse_err("--learn mode is not supported with --ipv6, beacuse there is no such thing as NAT66 (ipv6 to ipv6 translation) \n" \
                  "If you think it is important, please open a defect or write to TRex mailing list\n");
    }

    if (po->preview.get_is_rx_check_enable() ||  po->is_latency_enabled() || CGlobalInfo::is_learn_mode()
        || (CGlobalInfo::m_options.m_arp_ref_per != 0)
        || (!get_dpdk_mode()->is_hardware_filter_needed()) ) {
        po->set_rx_enabled();
    }

    if ( node_dump ){
        po->preview.setVMode(a);
    }

    if (po->m_platform_factor==0.0){
        parse_err(" you must provide a non zero multipler for platform -pm 0 is not valid \n");
    }

    /* if we have a platform factor we need to devided by it so we can still work with normalized yaml profile  */
    po->m_factor = po->m_factor/po->m_platform_factor;

    if (po->m_factor==0.0) {
        parse_err(" you must provide a non zero multipler -m 0 is not valid \n");
    }


    if ( first_time ){
        /* only first time read the configuration file */
        if ( po->platform_cfg_file.length() >0  ) {
            if ( node_dump ){
                printf("Using configuration file %s \n",po->platform_cfg_file.c_str());
            }
            cg->load_from_yaml_file(po->platform_cfg_file);
            if ( node_dump ){
                cg->Dump(stdout);
            }
        }else{
            if ( utl_is_file_exists("/etc/trex_cfg.yaml") ){
                if ( node_dump ){
                    printf("Using configuration file /etc/trex_cfg.yaml \n");
                }
                cg->load_from_yaml_file("/etc/trex_cfg.yaml");
                if ( node_dump ){
                    cg->Dump(stdout);
                }
            }
        }
    } else {
        if ( cg->m_if_list.size() > CGlobalInfo::m_options.m_expected_portd ) {
            cg->m_if_list.resize(CGlobalInfo::m_options.m_expected_portd);
        }
    }

    if ( get_is_interactive() ) {
        if ( opt_vlan_was_set ) {
            // Only purpose of this in interactive is for configuring the 82599 rules correctly
            po->preview.set_vlan_mode(CPreviewMode::VLAN_MODE_NORMAL);
        }

    } else {
        if ( !po->m_duration ) {
            po->m_duration = 3600.0;
        }
        if ( global_platform_cfg_info.m_tw.m_info_exist ){

            CTimerWheelYamlInfo *lp=&global_platform_cfg_info.m_tw;
            std::string  err;
            if (!lp->Verify(err)){
                parse_err(err);
            }

            po->set_tw_bucket_time_in_usec(lp->m_bucket_time_usec);
            po->set_tw_buckets(lp->m_buckets);
            po->set_tw_levels(lp->m_levels);
        }
    }


    return 0;
}

COLD_FUNC void free_args_copy(int argc, char **argv_copy) {
    for(int i=0; i<argc; i++) {
        free(argv_copy[i]);
    }
    free(argv_copy);
}

static int parse_options_wrapper(int argc, char *argv[], bool first_time ) {
    // copy, as arg parser sometimes changes the argv
    char ** argv_copy = (char **) malloc(sizeof(char *) * argc);
    for(int i=0; i<argc; i++) {
        argv_copy[i] = strdup(argv[i]);
    }
    int ret = 0;
    try {
        ret = parse_options(argc, argv_copy, first_time);
    } catch (ParsingOptException &e) {
        if (e.m_err_code == SO_OPT_INVALID) {
            printf("Error: option %s is not recognized.\n\n", e.m_opt_text);
        } else if (e.m_err_code == SO_ARG_MISSING) {
            printf("Error: option %s is expected to have argument.\n\n", e.m_opt_text);
        }
        free_args_copy(argc, argv_copy);
        usage();
        return -1;
    }

    free_args_copy(argc, argv_copy);
    return ret;
}

int main_test(int argc , char * argv[]);



/* this object is per core / per port / per queue
   each core will have 2 ports to send to


   port0                                port1

   0,1,2,3,..15 out queue ( per core )       0,1,2,3,..15 out queue ( per core )

*/

COLD_FUNC uint16_t get_client_side_vlan(CVirtualIF * _ifs){
    CCoreEthIFTcp * lpif=(CCoreEthIFTcp *)_ifs;
    CCorePerPort *lp_port = (CCorePerPort *)lpif->get_ports();
    uint8_t port_id = lp_port->m_port->get_tvpid();
    uint16_t vlan=CGlobalInfo::m_options.m_ip_cfg[port_id].get_vlan();
    return(vlan);
}

COLD_FUNC bool CCoreEthIF::Create(uint8_t             core_id,
                        uint8_t             tx_client_queue_id,
                        CPhyEthIF  *        tx_client_port,
                        uint8_t             tx_server_queue_id,
                        CPhyEthIF  *        tx_server_port,
                        uint8_t tx_q_id_lat ) {
    m_ports[CLIENT_SIDE].m_tx_queue_id = tx_client_queue_id;
    m_ports[CLIENT_SIDE].m_port        = tx_client_port;
    m_ports[CLIENT_SIDE].m_tx_queue_id_lat = tx_q_id_lat;
    m_ports[SERVER_SIDE].m_tx_queue_id = tx_server_queue_id;
    m_ports[SERVER_SIDE].m_port        = tx_server_port;
    m_ports[SERVER_SIDE].m_tx_queue_id_lat = tx_q_id_lat;
    m_core_id = core_id;

    CMessagingManager * rx_dp=CMsgIns::Ins()->getRxDp();
    m_ring_to_rx = rx_dp->getRingDpToCp(core_id-1);
    assert( m_ring_to_rx);
    return (true);
}

COLD_FUNC int CCoreEthIF::flush_tx_queue(void){
    /* flush both sides */
    pkt_dir_t dir;
    for (dir = CLIENT_SIDE; dir < CS_NUM; dir++) {
        CCorePerPort * lp_port = &m_ports[dir];
        CVirtualIFPerSideStats  * lp_stats = &m_stats[dir];
        if ( likely(lp_port->m_len > 0) ) {
            send_burst(lp_port, lp_port->m_len, lp_stats);
            lp_port->m_len = 0;
        }
    }

    return 0;
}

COLD_FUNC void CCoreEthIF::GetCoreCounters(CVirtualIFPerSideStats *stats){
    stats->Clear();
    pkt_dir_t   dir ;
    for (dir=CLIENT_SIDE; dir<CS_NUM; dir++) {
        stats->Add(&m_stats[dir]);
    }
}

COLD_FUNC void CCoreEthIF::DumpCoreStats(FILE *fd){
    fprintf (fd,"------------------------ \n");
    fprintf (fd," per core stats core id : %d  \n",m_core_id);
    fprintf (fd,"------------------------ \n");

    CVirtualIFPerSideStats stats;
    GetCoreCounters(&stats);
    stats.Dump(stdout);
}

COLD_FUNC void CCoreEthIF::DumpIfCfgHeader(FILE *fd){
    fprintf (fd," core, c-port, c-queue, s-port, s-queue, lat-queue\n");
    fprintf (fd," ------------------------------------------\n");
}

COLD_FUNC void CCoreEthIF::DumpIfCfg(FILE *fd){
    fprintf (fd," %d   %6u %6u  %6u  %6u %6u  \n",m_core_id,
             m_ports[CLIENT_SIDE].m_port->get_tvpid(),
             m_ports[CLIENT_SIDE].m_tx_queue_id,
             m_ports[SERVER_SIDE].m_port->get_tvpid(),
             m_ports[SERVER_SIDE].m_tx_queue_id,
             m_ports[SERVER_SIDE].m_tx_queue_id_lat
             );
}

COLD_FUNC void CCoreEthIF::DumpIfStats(FILE *fd){

    fprintf (fd,"------------------------ \n");
    fprintf (fd," per core per if stats id : %d  \n",m_core_id);
    fprintf (fd,"------------------------ \n");

    const char * t[]={"client","server"};
    pkt_dir_t   dir ;
    for (dir=CLIENT_SIDE; dir<CS_NUM; dir++) {
        CCorePerPort * lp=&m_ports[dir];
        CVirtualIFPerSideStats * lpstats = &m_stats[dir];
        fprintf (fd," port %d, queue id :%d  - %s \n",lp->m_port->get_tvpid(),lp->m_tx_queue_id,t[dir] );
        fprintf (fd," ---------------------------- \n");
        lpstats->Dump(fd);
    }
}

/**
 * when measureing performance with perf prefer drop in case of 
 * queue full 
 * this will allow us actually measure the max B/W possible 
 * without the noise of retrying 
 */

HOT_FUNC int  CCoreEthIF::send_burst(CCorePerPort * lp_port,
                           uint16_t len,
                           CVirtualIFPerSideStats  * lp_stats){

    uint16_t ret = lp_port->m_port->tx_burst(lp_port->m_tx_queue_id,lp_port->m_table,len);
    if (likely( CGlobalInfo::m_options.m_is_queuefull_retry )) {
        while ( unlikely( ret<len ) ){
            rte_delay_us(1);
            lp_stats->m_tx_queue_full += 1;
            uint16_t ret1=lp_port->m_port->tx_burst(lp_port->m_tx_queue_id,
                                                    &lp_port->m_table[ret],
                                                    len-ret);
            ret+=ret1;
        }
    } else {
        /* CPU has burst of packets larger than TX can send. Need to drop packets */
        if ( unlikely(ret < len) ) {
            lp_stats->m_tx_drop += (len-ret);
            uint16_t i;
            for (i=ret; i<len;i++) {
                rte_mbuf_t * m=lp_port->m_table[i];
                rte_pktmbuf_free(m);
            }
        }
    }

    return (0);
}

int HOT_FUNC CCoreEthIF::send_pkt(CCorePerPort * lp_port,
                         rte_mbuf_t      *m,
                         CVirtualIFPerSideStats  * lp_stats
                         ){

    uint16_t len = lp_port->m_len;
    lp_port->m_table[len]=m;
    len++;

    /* enough pkts to be sent */
    if (unlikely(len == MAX_PKT_BURST)) {
        send_burst(lp_port, MAX_PKT_BURST,lp_stats);
        len = 0;
    }
    lp_port->m_len = len;

    return (0);
}

HOT_FUNC int CCoreEthIF::send_pkt_lat(CCorePerPort *lp_port, rte_mbuf_t *m, CVirtualIFPerSideStats *lp_stats) {
    // We allow sending only from first core of each port. This is serious internal bug otherwise.
    assert(lp_port->m_tx_queue_id_lat != INVALID_Q_ID);

    int ret = lp_port->m_port->tx_burst(lp_port->m_tx_queue_id_lat, &m, 1);

    if (likely( CGlobalInfo::m_options.m_is_queuefull_retry )) {
        while ( unlikely( ret != 1 ) ){
            rte_delay_us(1);
            lp_stats->m_tx_queue_full += 1;
            ret = lp_port->m_port->tx_burst(lp_port->m_tx_queue_id_lat, &m, 1);
        }
    } else {
        if ( unlikely( ret != 1 ) ) {
            lp_stats->m_tx_drop ++;
            rte_pktmbuf_free(m);
            return 0;
        }
    }
    return ret;
}

HOT_FUNC void CCoreEthIF::send_one_pkt(pkt_dir_t       dir,
                              rte_mbuf_t      *m){
    CCorePerPort *  lp_port=&m_ports[dir];
    CVirtualIFPerSideStats  * lp_stats = &m_stats[dir];
    send_pkt(lp_port,m,lp_stats);
    /* flush */
    send_burst(lp_port,lp_port->m_len,lp_stats);
    lp_port->m_len = 0;
}

HOT_FUNC uint16_t CCoreEthIFTcp::rx_burst(pkt_dir_t dir,
                                 struct rte_mbuf **rx_pkts,
                                 uint16_t nb_pkts){
    uint16_t res = m_ports[dir].m_port->rx_burst(m_rx_queue_id[dir],rx_pkts,nb_pkts);
    return (res);
}

HOT_FUNC int CCoreEthIFTcp::send_node(CGenNode *node){
    CNodeTcp * node_tcp = (CNodeTcp *) node;
    uint8_t dir=node_tcp->dir;
    CCorePerPort *lp_port = &m_ports[dir];
    CVirtualIFPerSideStats *lp_stats = &m_stats[dir];
    TrexCaptureMngr::getInstance().handle_pkt_tx(node_tcp->mbuf, lp_port->m_port->get_tvpid());
    send_pkt(lp_port,node_tcp->mbuf,lp_stats);
    return (0);
}

HOT_FUNC int CCoreEthIFStateless::send_node_flow_stat(rte_mbuf *m, CGenNodeStateless * node_sl, CCorePerPort *  lp_port
                                             , CVirtualIFPerSideStats  * lp_stats, bool is_const) {
    // Defining this makes 10% percent packet loss. 1% packet reorder.
# ifdef ERR_CNTRS_TEST
    static int temp=1;
    temp++;
#endif

    uint16_t hw_id = node_sl->get_stat_hw_id();
    rte_mbuf *mi;
    struct flow_stat_payload_header *fsp_head = NULL;

    if (hw_id >= MAX_FLOW_STATS) {
        // payload rule hw_ids are in the range right above ip id rules
        uint16_t hw_id_payload = hw_id - MAX_FLOW_STATS;

        mi = node_sl->alloc_flow_stat_mbuf(m, fsp_head, is_const);
        fsp_head->seq = lp_stats->m_lat_data[hw_id_payload].get_seq_num();
        fsp_head->hw_id = hw_id_payload;
        fsp_head->flow_seq = lp_stats->m_lat_data[hw_id_payload].get_flow_seq();
        fsp_head->magic = FLOW_STAT_PAYLOAD_MAGIC;

        lp_stats->m_lat_data[hw_id_payload].inc_seq_num();
#ifdef ERR_CNTRS_TEST
        if (temp % 10 == 0) {
            fsp_head->seq = lp_stats->m_lat_data[hw_id_payload].inc_seq_num();
        }
        if ((temp - 1) % 100 == 0) {
            fsp_head->seq = lp_stats->m_lat_data[hw_id_payload].get_seq_num() - 4;
        }
#endif
    } else {
        // ip id rule
        mi = m;
    }
    tx_per_flow_t *lp_s = &lp_stats->m_tx_per_flow[hw_id];
    lp_s->add_pkts(1);
    lp_s->add_bytes(mi->pkt_len + 4); // We add 4 because of ethernet CRC

    if (hw_id >= MAX_FLOW_STATS) {
        // TIME EXPERIMENT
        // fsp_head->time_stamp = os_get_hr_tick_64();
        fsp_head->time_stamp = get_time_epoch_nanoseconds();

        send_pkt_lat(lp_port, mi, lp_stats);
    } else {
        send_pkt(lp_port, mi, lp_stats);
    }
    return 0;
}

HOT_FUNC inline rte_mbuf_t *
CCoreEthIFStateless::generate_node_pkt(CGenNodeStateless *node_sl) {
    if (unlikely(node_sl->get_is_slow_path())) {
        return generate_slow_path_node_pkt(node_sl);
    }

    /* check that we have mbuf  */
    rte_mbuf_t *m;

    if ( likely(node_sl->is_cache_mbuf_array()) ) {
        m = node_sl->cache_mbuf_array_get_cur();
        rte_pktmbuf_refcnt_update(m,1);
    }else{
        m = node_sl->get_cache_mbuf();

        if (m) {
            /* cache case */
            rte_pktmbuf_refcnt_update(m,1);
        }else{
            m=node_sl->alloc_node_with_vm();
            assert(m);
        }
    }

    return m;
}

HOT_FUNC inline int
CCoreEthIFStateless::send_node_packet(CGenNodeStateless      *node_sl,
                                      rte_mbuf_t             *m,
                                      CCorePerPort           *lp_port,
                                      CVirtualIFPerSideStats *lp_stats) {

    if (unlikely(node_sl->is_stat_needed())) {
        if ( unlikely(node_sl->is_cache_mbuf_array()) ) {
            // No support for latency + cache. If user asks for cache on latency stream, we change cache to 0.
            // assert here just to make sure.
            assert(1);
        }
        return send_node_flow_stat(m, node_sl, lp_port, lp_stats, (node_sl->get_cache_mbuf()) ? true : false);
    } else {
        return send_pkt(lp_port, m, lp_stats);
    }
}

HOT_FUNC uint16_t CCoreEthIFStateless::rx_burst(pkt_dir_t dir,
                                 struct rte_mbuf **rx_pkts,
                                 uint16_t nb_pkts){
    uint16_t res = m_ports[dir].m_port->rx_burst(m_rx_queue_id[dir],rx_pkts,nb_pkts);
    return (res);
}


HOT_FUNC int CCoreEthIFStateless::send_node(CGenNode *node) {
    return send_node_common<false>(node);
}

HOT_FUNC int CCoreEthIFStateless::send_node_service_mode(CGenNode *node) {
    return send_node_common<true>(node);
}

/**
 * this is the common function and it is templated
 * for two compiler evaluation for performance
 *
 */
template <bool SERVICE_MODE> HOT_FUNC
int CCoreEthIFStateless::send_node_common(CGenNode *node) {
    CGenNodeStateless * node_sl = (CGenNodeStateless *) node;

    pkt_dir_t dir                     = (pkt_dir_t)node_sl->get_mbuf_cache_dir();
    CCorePerPort *lp_port             = &m_ports[dir];
    CVirtualIFPerSideStats *lp_stats  = &m_stats[dir];

    /* generate packet (can never fail) */
    rte_mbuf_t *m = generate_node_pkt(node_sl);

    /* template boolean - this will be removed at compile time */
    if (SERVICE_MODE) {
        TrexCaptureMngr::getInstance().handle_pkt_tx(m, lp_port->m_port->get_tvpid());
    }

    /* send */
    return send_node_packet(node_sl, m, lp_port, lp_stats);
}

/**
 * slow path code goes here
 *
 */
rte_mbuf_t *
CCoreEthIFStateless::generate_slow_path_node_pkt(CGenNodeStateless *node_sl) {

    if (node_sl->m_type == CGenNode::PCAP_PKT) {
        CGenNodePCAP *pcap_node = (CGenNodePCAP *)node_sl;
        return pcap_node->get_pkt();
    }

    /* unhandled case of slow path node */
    assert(0);
    return (NULL);
}


/**
 * slow path features goes here (avoid multiple IFs)
 *
 */
void CCoreEthIF::handle_slowpath_features(CGenNode *node, rte_mbuf_t *m, uint8_t *p, pkt_dir_t dir) {


    uint8_t mac_ip_overide_mode = CGlobalInfo::m_options.preview.get_mac_ip_overide_mode();
    if ( unlikely( mac_ip_overide_mode ) ) {
        switch ( mac_ip_overide_mode ) {
            case 1: /* MAC override, only src at client side */
                /* client side */
                if ( node->is_initiator_pkt() ) {
                    *((uint32_t*)(p+8)) = PKT_NTOHL(node->m_src_ip);
                }
                break;
            case 2: /* MAC override, all directions */
                if ( node->is_initiator_pkt() ) {
                    *((uint32_t*)(p+8)) = PKT_NTOHL(node->m_src_ip);
                    *((uint32_t*)(p+2)) = PKT_NTOHL(node->m_dest_ip);
                } else {
                    *((uint32_t*)(p+8)) = PKT_NTOHL(node->m_dest_ip);
                    *((uint32_t*)(p+2)) = PKT_NTOHL(node->m_src_ip);
                }
                break;
            default:
                assert(0);
        }
    }

    /* flag is faster than checking the node pointer (another cacheline) */
    if ( unlikely(CGlobalInfo::m_options.preview.get_is_client_cfg_enable() ) ) {
        assert(node->m_client_cfg);
        node->m_client_cfg->apply(m, dir);
    }

}

HOT_FUNC bool CCoreEthIF::redirect_to_rx_core(pkt_dir_t   dir,
                                     rte_mbuf_t * m){
    bool sent=false;

    CGenNodeLatencyPktInfo * node=(CGenNodeLatencyPktInfo * )CGlobalInfo::create_node();
    if ( node ) {
        node->m_msg_type = CGenNodeMsgBase::LATENCY_PKT;
        node->m_dir      = dir;
        node->m_latency_offset = 0xdead;
        node->m_pkt      = m;
        if ( m_ring_to_rx->Enqueue((CGenNode*)node)==0 ){
            sent=true;
        }else{
            rte_pktmbuf_free(m);
            CGlobalInfo::free_node((CGenNode *)node);
        }

#ifdef LATENCY_QUEUE_TRACE_
        printf("rx to cp --\n");
        rte_pktmbuf_dump(stdout,m, rte_pktmbuf_pkt_len(m));
#endif
    }

    if (sent==false) {
        /* inc counter */
        CVirtualIFPerSideStats *lp_stats = &m_stats[dir];
        lp_stats->m_tx_redirect_error++;
    }
    return (sent);
}

HOT_FUNC  int CCoreEthIF::send_node(CGenNode * node) {


    CFlowPktInfo *  lp=node->m_pkt_info;
    rte_mbuf_t *    m=lp->generate_new_mbuf(node);

    pkt_dir_t       dir;
    bool            single_port;

    dir         = node->cur_interface_dir();
    single_port = node->get_is_all_flow_from_same_dir() ;


    if ( unlikely(CGlobalInfo::m_options.preview.get_vlan_mode()
                  != CPreviewMode::VLAN_MODE_NONE) ) {
        uint16_t vlan_id=0;

        if (CGlobalInfo::m_options.preview.get_vlan_mode()
            == CPreviewMode::VLAN_MODE_LOAD_BALANCE) {
            /* which vlan to choose 0 or 1*/
            uint8_t vlan_port = (node->m_src_ip & 1);
            vlan_id = CGlobalInfo::m_options.m_vlan_port[vlan_port];
            if (likely( vlan_id > 0 ) ) {
                dir = dir ^ vlan_port;
            } else {
                /* both from the same dir but with VLAN0 */
                vlan_id = CGlobalInfo::m_options.m_vlan_port[0];
            }
        } else if (CGlobalInfo::m_options.preview.get_vlan_mode()
            == CPreviewMode::VLAN_MODE_NORMAL) {
            CCorePerPort *lp_port = &m_ports[dir];
            uint8_t port_id = lp_port->m_port->get_tvpid();
            vlan_id = CGlobalInfo::m_options.m_ip_cfg[port_id].get_vlan();
        }

        add_vlan(m, vlan_id);
    }

    CCorePerPort *lp_port = &m_ports[dir];
    CVirtualIFPerSideStats *lp_stats = &m_stats[dir];

    if (unlikely(m==0)) {
        lp_stats->m_tx_alloc_error++;
        return(0);
    }

    /* update mac addr dest/src 12 bytes */
    uint8_t *p   = rte_pktmbuf_mtod(m, uint8_t*);
    uint8_t p_id = lp_port->m_port->get_tvpid();

    memcpy(p,CGlobalInfo::m_options.get_dst_src_mac_addr(p_id),12);

     /* when slowpath features are on */
    if ( unlikely( CGlobalInfo::m_options.preview.get_is_slowpath_features_on() ) ) {
        handle_slowpath_features(node, m, p, dir);
    }


    if ( unlikely( node->is_rx_check_enabled() ) ) {
        lp_stats->m_tx_rx_check_pkt++;
        lp->do_generate_new_mbuf_rxcheck(m, node, single_port);
        lp_stats->m_template.inc_template( node->get_template_id( ));
    }

    /*printf("send packet -- \n");
      rte_pktmbuf_dump(stdout,m, rte_pktmbuf_pkt_len(m));*/

    /* send the packet */
    send_pkt(lp_port,m,lp_stats);
    return (0);
}

int CCoreEthIF::update_mac_addr_from_global_cfg(pkt_dir_t  dir, uint8_t * p){
    assert(p);
    assert(dir<2);

    CCorePerPort *  lp_port=&m_ports[dir];
    uint8_t p_id=lp_port->m_port->get_tvpid();
    memcpy(p,CGlobalInfo::m_options.get_dst_src_mac_addr(p_id),12);
    return (0);
}

pkt_dir_t
CCoreEthIF::port_id_to_dir(uint8_t port_id) {

    for (pkt_dir_t dir = 0; dir < CS_NUM; dir++) {
        if (m_ports[dir].m_port->get_tvpid() == port_id) {
            return dir;
        }
    }

    return (CS_INVALID);
}

/**
 * apply HW VLAN
 */
void
CPortLatencyHWBase::apply_hw_vlan(rte_mbuf_t *m, uint8_t port_id) {

    uint8_t vlan_mode = CGlobalInfo::m_options.preview.get_vlan_mode();
    if ( likely( vlan_mode != CPreviewMode::VLAN_MODE_NONE) ) {
        if ( vlan_mode == CPreviewMode::VLAN_MODE_LOAD_BALANCE ) {
            add_vlan(m, CGlobalInfo::m_options.m_vlan_port[0]);
        } else if (vlan_mode == CPreviewMode::VLAN_MODE_NORMAL) {
            add_vlan(m, CGlobalInfo::m_options.m_ip_cfg[port_id].get_vlan());
        }
    }
}

COLD_FUNC std::string CGlobalStats::get_field(const char *name, float &f){
    char buff[200];
    if(f <= -10.0 or f >= 10.0)
        snprintf(buff, sizeof(buff), "\"%s\":%.1f,",name,f);
    else
        snprintf(buff, sizeof(buff), "\"%s\":%.3e,",name,f);
    return (std::string(buff));
}

COLD_FUNC std::string CGlobalStats::get_field(const char *name, uint64_t &f){
    char buff[200];
    snprintf(buff,  sizeof(buff), "\"%s\":%llu,", name, (unsigned long long)f);
    return (std::string(buff));
}

COLD_FUNC std::string CGlobalStats::get_field_port(int port, const char *name, float &f){
    char buff[200];
    if(f <= -10.0 or f >= 10.0)
        snprintf(buff,  sizeof(buff), "\"%s-%d\":%.1f,", name, port, f);
    else
        snprintf(buff, sizeof(buff), "\"%s-%d\":%.3e,", name, port, f);
    return (std::string(buff));
}

COLD_FUNC std::string CGlobalStats::get_field_port(int port, const char *name, uint64_t &f){
    char buff[200];
    snprintf(buff, sizeof(buff), "\"%s-%d\":%llu,",name, port, (unsigned long long)f);
    return (std::string(buff));
}

COLD_FUNC void CGlobalStats::dump_json(std::string & json, bool baseline){
    /* refactor this to JSON */

    json="{\"name\":\"trex-global\",\"type\":0,";
    if (baseline) {
        json += "\"baseline\": true,";
    }

    json +="\"data\":{";

    char ts_buff[200];
    snprintf(ts_buff , sizeof(ts_buff), "\"ts\":{\"value\":%lu, \"freq\":%lu},", os_get_hr_tick_64(), os_get_hr_freq());
    json+= std::string(ts_buff);

#define GET_FIELD(f) get_field(#f, f)
#define GET_FIELD_PORT(p,f) get_field_port(p, #f, lp->f)

    json+=GET_FIELD(m_cpu_util);
    json+=GET_FIELD(m_cpu_util_raw);
    json+=GET_FIELD(m_bw_per_core);
    json+=GET_FIELD(m_rx_cpu_util);
    json+=GET_FIELD(m_rx_core_pps);
    json+=GET_FIELD(m_platform_factor);
    json+=GET_FIELD(m_tx_bps);
    json+=GET_FIELD(m_rx_bps);
    json+=GET_FIELD(m_tx_pps);
    json+=GET_FIELD(m_rx_pps);
    json+=GET_FIELD(m_tx_cps);
    json+=GET_FIELD(m_tx_expected_cps);
    json+=GET_FIELD(m_tx_expected_pps);
    json+=GET_FIELD(m_tx_expected_bps);
    json+=GET_FIELD(m_total_alloc_error);
    json+=GET_FIELD(m_total_queue_full);
    json+=GET_FIELD(m_total_queue_drop);
    json+=GET_FIELD(m_rx_drop_bps);
    json+=GET_FIELD(m_active_flows);
    json+=GET_FIELD(m_open_flows);

    json+=GET_FIELD(m_total_tx_pkts);
    json+=GET_FIELD(m_total_rx_pkts);
    json+=GET_FIELD(m_total_tx_bytes);
    json+=GET_FIELD(m_total_rx_bytes);

    json+=GET_FIELD(m_total_clients);
    json+=GET_FIELD(m_total_servers);
    json+=GET_FIELD(m_active_sockets);
    json+=GET_FIELD(m_socket_util);

    json+=GET_FIELD(m_total_nat_time_out);
    json+=GET_FIELD(m_total_nat_time_out_wait_ack);
    json+=GET_FIELD(m_total_nat_no_fid );
    json+=GET_FIELD(m_total_nat_active );
    json+=GET_FIELD(m_total_nat_syn_wait);
    json+=GET_FIELD(m_total_nat_open   );
    json+=GET_FIELD(m_total_nat_learn_error);

    int i;
    for (i=0; i<(int)m_num_of_ports; i++) {
        if ( CTVPort(i).is_dummy() ) {
            continue;
        }
        CPerPortStats * lp=&m_port[i];
        json+=GET_FIELD_PORT(i,opackets) ;
        json+=GET_FIELD_PORT(i,obytes)   ;
        json+=GET_FIELD_PORT(i,ipackets) ;
        json+=GET_FIELD_PORT(i,ibytes)   ;
        json+=GET_FIELD_PORT(i,ierrors)  ;
        json+=GET_FIELD_PORT(i,oerrors)  ;
        json+=GET_FIELD_PORT(i,m_total_tx_bps);
        json+=GET_FIELD_PORT(i,m_total_tx_pps);
        json+=GET_FIELD_PORT(i,m_total_rx_bps);
        json+=GET_FIELD_PORT(i,m_total_rx_pps);
        json+=GET_FIELD_PORT(i,m_cpu_util);
    }
    json+=m_template.dump_as_json("template");
    json+="\"unknown\":0}}"  ;
}

COLD_FUNC void CGlobalStats::global_stats_to_json(Json::Value &output) {

    output["m_cpu_util"] = m_cpu_util;
    output["m_cpu_util_raw"] = m_cpu_util_raw;
    output["m_bw_per_core"] = m_bw_per_core;
    output["m_rx_cpu_util"] = m_rx_cpu_util;
    output["m_rx_core_pps"] = m_rx_core_pps;
    output["m_platform_factor"] = m_platform_factor;
    output["m_tx_bps"] = m_tx_bps;
    output["m_rx_bps"] = m_rx_bps;
    output["m_tx_pps"] = m_tx_pps;
    output["m_rx_pps"] = m_rx_pps;
    output["m_tx_cps"] = m_tx_cps;
    output["m_tx_expected_cps"] = m_tx_expected_cps;
    output["m_tx_expected_pps"] = m_tx_expected_pps;
    output["m_tx_expected_bps"] = m_tx_expected_bps;
    output["m_total_alloc_error"] = m_total_alloc_error;
    output["m_total_queue_full"] = m_total_queue_full;
    output["m_total_queue_drop"] = m_total_queue_drop;
    output["m_rx_drop_bps"] = m_rx_drop_bps;
    output["m_active_flows"] = m_active_flows;
    output["m_open_flows"] = m_open_flows;
    output["m_total_tx_pkts"] = m_total_tx_pkts;
    output["m_total_rx_pkts"] = m_total_rx_pkts;
    output["m_total_tx_bytes"] = m_total_tx_bytes;
    output["m_total_rx_bytes"] = m_total_rx_bytes;
    output["m_total_clients"] = m_total_clients;
    output["m_total_servers"] = m_total_servers;
    output["m_active_sockets"] = m_active_sockets;
    output["m_socket_util"] = m_socket_util;
    output["m_total_nat_time_out"] = m_total_nat_time_out;
    output["m_total_nat_time_out_wait_ack"] = m_total_nat_time_out_wait_ack;
    output["m_total_nat_no_fid "] = m_total_nat_no_fid ;
    output["m_total_nat_active "] = m_total_nat_active ;
    output["m_total_nat_syn_wait"] = m_total_nat_syn_wait;
    output["m_total_nat_open   "] = m_total_nat_open   ;
    output["m_total_nat_learn_error"] = m_total_nat_learn_error;
}

COLD_FUNC bool CGlobalStats::is_dump_nat() {
  return (CGlobalInfo::is_learn_mode() && (get_is_tcp_mode() == 0));
}

COLD_FUNC void CGlobalStats::port_stats_to_json(Json::Value &output,
                                               uint8_t port_id) {
  CPerPortStats *lp = &m_port[port_id];

  output["opackets"] = lp->opackets;
  output["obytes"] = lp->obytes;
  output["ipackets"] = lp->ipackets;
  output["ibytes"] = lp->ibytes;
  output["ierrors"] = lp->ierrors;
  output["oerrors"] = lp->oerrors;
  output["m_total_tx_bps"] = lp->m_total_tx_bps;
  output["m_total_tx_pps"] = lp->m_total_tx_pps;
  output["m_total_rx_bps"] = lp->m_total_rx_bps;
  output["m_total_rx_pps"] = lp->m_total_rx_pps;
  output["m_cpu_util"] = lp->m_cpu_util;
}

COLD_FUNC void CGlobalStats::DumpAllPorts(FILE *fd){


    if ( m_cpu_util > 0.1 ) {
        fprintf (fd," Cpu Utilization : %2.1f  %%  %2.1f Gb/core \n", m_cpu_util, m_bw_per_core);
    } else {
        fprintf (fd," Cpu Utilization : %2.1f  %%\n", m_cpu_util);
    }
    fprintf (fd," Platform_factor : %2.1f  \n",m_platform_factor);
    fprintf (fd," Total-Tx        : %s  ",double_to_human_str(m_tx_bps,"bps",KBYE_1000).c_str());
    if ( is_dump_nat() ) {
        fprintf (fd," NAT time out    : %8llu", (unsigned long long)m_total_nat_time_out);
        if (CGlobalInfo::is_learn_mode(CParserOption::LEARN_MODE_TCP_ACK)) {
            fprintf (fd," (%llu in wait for syn+ack)\n", (unsigned long long)m_total_nat_time_out_wait_ack);
        } else {
            fprintf (fd, "\n");
        }
    }else{
        fprintf (fd,"\n");
    }


    fprintf (fd," Total-Rx        : %s  ",double_to_human_str(m_rx_bps,"bps",KBYE_1000).c_str());
    if ( is_dump_nat() ) {
        fprintf (fd," NAT aged flow id: %8llu \n", (unsigned long long)m_total_nat_no_fid);
    }else{
        fprintf (fd,"\n");
    }

    fprintf (fd," Total-PPS       : %s  ",double_to_human_str(m_tx_pps,"pps",KBYE_1000).c_str());
    if ( is_dump_nat() ) {
        fprintf (fd," Total NAT active: %8llu", (unsigned long long)m_total_nat_active);
        if (CGlobalInfo::is_learn_mode(CParserOption::LEARN_MODE_TCP_ACK)) {
            fprintf (fd," (%llu waiting for syn)\n", (unsigned long long)m_total_nat_syn_wait);
        } else {
            fprintf (fd, "\n");
        }
    }else{
        fprintf (fd,"\n");
    }

    fprintf (fd," Total-CPS       : %s  ",double_to_human_str(m_tx_cps,"cps",KBYE_1000).c_str());
    if ( is_dump_nat() ) {
        fprintf (fd," Total NAT opened: %8llu \n", (unsigned long long)m_total_nat_open);
    }else{
        fprintf (fd,"\n");
    }
    fprintf (fd,"\n");
    fprintf (fd," Expected-PPS    : %s  ",double_to_human_str(m_tx_expected_pps,"pps",KBYE_1000).c_str());
    if ( is_dump_nat() && CGlobalInfo::is_learn_verify_mode() ) {
        fprintf (fd," NAT learn errors: %8llu \n", (unsigned long long)m_total_nat_learn_error);
    }else{
        fprintf (fd,"\n");
    }
    fprintf (fd," Expected-CPS    : %s  \n",double_to_human_str(m_tx_expected_cps,"cps",KBYE_1000).c_str());
    fprintf (fd," Expected-%s : %s  \n", get_is_tcp_mode() ? "L7-BPS" : "BPS   "
             ,double_to_human_str(m_tx_expected_bps,"bps",KBYE_1000).c_str());
    fprintf (fd,"\n");
    fprintf (fd," Active-flows    : %8llu  Clients : %8llu   Socket-util : %3.4f %%    \n",
             (unsigned long long)m_active_flows,
             (unsigned long long)m_total_clients,
             m_socket_util);
    fprintf (fd," Open-flows      : %8llu  Servers : %8llu   Socket : %8llu Socket/Clients :  %.1f \n",
             (unsigned long long)m_open_flows,
             (unsigned long long)m_total_servers,
             (unsigned long long)m_active_sockets,
             (float)m_active_sockets/(float)m_total_clients);

    if (m_total_alloc_error) {
        fprintf (fd," Total_alloc_err  : %llu         \n", (unsigned long long)m_total_alloc_error);
    }
    if ( m_total_queue_full ){
        fprintf (fd," Total_queue_full : %llu         \n", (unsigned long long)m_total_queue_full);
    }
    if (m_total_queue_drop) {
        fprintf (fd," Total_queue_drop : %llu         \n", (unsigned long long)m_total_queue_drop);
    }

    //m_template.Dump(fd);

    fprintf (fd," drop-rate       : %s   \n",double_to_human_str(m_rx_drop_bps,"bps",KBYE_1000).c_str() );
}

COLD_FUNC void CGlobalStats::Dump(FILE *fd,DumpFormat mode){
    int i;
    int port_to_show=m_num_of_ports;
    if (port_to_show>4) {
        port_to_show=4;
        fprintf (fd," per port - limited to 4   \n");
    }


    if ( mode== dmpSTANDARD ){
        fprintf (fd," --------------- \n");
        for (i=0; i<(int)port_to_show; i++) {
            if ( CTVPort(i).is_dummy() ) {
                continue;
            }
            CPerPortStats * lp=&m_port[i];
            fprintf(fd,"port : %d ",(int)i);
            if ( ! lp->m_link_up ) {
                fprintf(fd," (link DOWN)");
            }
            fprintf(fd,"\n------------\n");
#define GS_DP_A4(f) fprintf(fd," %-40s : %llu \n",#f, (unsigned long long)lp->f)
#define GS_DP_A(f) if (lp->f) fprintf(fd," %-40s : %llu \n",#f, (unsigned long long)lp->f)
            GS_DP_A4(opackets);
            GS_DP_A4(obytes);
            GS_DP_A4(ipackets);
            GS_DP_A4(ibytes);
            GS_DP_A(ierrors);
            GS_DP_A(oerrors);
            fprintf (fd," Tx : %s  \n",double_to_human_str((double)lp->m_total_tx_bps,"bps",KBYE_1000).c_str());
        }
    }else{
        fprintf(fd," %10s ","ports");
        for (i=0; i<(int)port_to_show; i++) {
            if ( CTVPort(i).is_dummy() ) {
                continue;
            }
            CPerPortStats * lp=&m_port[i];
            if ( lp->m_link_up ) {
                fprintf(fd,"| %15d ",i);
            } else {
                std::string port_with_state = "(link DOWN) " + std::to_string(i);
                fprintf(fd,"| %15s ",port_with_state.c_str());
            }
        }
        fprintf(fd,"\n");
        fprintf(fd," -----------------------------------------------------------------------------------------\n");
        std::string names[]={"opackets","obytes","ipackets","ibytes","ierrors","oerrors","Tx Bw"
        };
        for (i=0; i<7; i++) {
            fprintf(fd," %10s ",names[i].c_str());
            int j=0;
            for (j=0; j<port_to_show;j++) {
                if ( CTVPort(j).is_dummy() ) {
                    continue;
                }
                CPerPortStats * lp=&m_port[j];
                uint64_t cnt;
                switch (i) {
                case 0:
                    cnt=lp->opackets;
                    fprintf(fd,"| %15lu ",cnt);

                    break;
                case 1:
                    cnt=lp->obytes;
                    fprintf(fd,"| %15lu ",cnt);

                    break;
                case 2:
                    cnt=lp->ipackets;
                    fprintf(fd,"| %15lu ",cnt);

                    break;
                case 3:
                    cnt=lp->ibytes;
                    fprintf(fd,"| %15lu ",cnt);

                    break;
                case 4:
                    cnt=lp->ierrors;
                    fprintf(fd,"| %15lu ",cnt);

                    break;
                case 5:
                    cnt=lp->oerrors;
                    fprintf(fd,"| %15lu ",cnt);

                    break;
                case 6:
                    fprintf(fd,"| %15s ",double_to_human_str((double)lp->m_total_tx_bps,"bps",KBYE_1000).c_str());
                    break;
                default:
                    cnt=0xffffff;
                }
            } /* ports */
            fprintf(fd, "\n");
        }/* fields*/
    }
}

COLD_FUNC void  dump_dpdk_devices(void){
        printf(" DPDK devices %d : %d \n", rte_eth_dev_count(),
         rte_eth_dev_count_total());
        printf("-----\n");  
        char name[100];
        int j;
        for (j=0; j < rte_eth_dev_count_total(); j++){
            if (rte_eth_dev_get_name_by_port((uint16_t)j,name) == 0) {
                printf(" %d : vdev %s \n",j,name);
            }
        }
        printf("-----\n");
}

COLD_FUNC TrexSTX * get_stx() {
    return g_trex.m_stx;
}

/**
 * handles an abort
 *
 */
COLD_FUNC void abort_gracefully(const std::string &on_stdout,
                      const std::string &on_publisher) {

    g_trex.abort_gracefully(on_stdout, on_publisher);
}


HOT_FUNC static int latency_one_lcore(__attribute__((unused)) void *dummy)
{
    CPlatformSocketInfo * lpsock=&CGlobalInfo::m_socket;
    physical_thread_id_t  phy_id =rte_lcore_id();

    if ( lpsock->thread_phy_is_rx(phy_id) ) {
        g_trex.run_in_rx_core();
    }else{

        if ( lpsock->thread_phy_is_master( phy_id ) ) {
            g_trex.run_in_master();
            delay(1);
        }else{
            delay((uint32_t)(1000.0*CGlobalInfo::m_options.m_duration));
            /* this core has stopped */
            g_trex.m_signal[ lpsock->thread_phy_to_virt( phy_id ) ]=1;
        }
    }
    return 0;
}



HOT_FUNC static int slave_one_lcore(__attribute__((unused)) void *dummy)
{
    CPlatformSocketInfo * lpsock=&CGlobalInfo::m_socket;
    physical_thread_id_t  phy_id =rte_lcore_id();

    if ( lpsock->thread_phy_is_rx(phy_id) ) {
        g_trex.run_in_rx_core();
    }else{
        if ( lpsock->thread_phy_is_master( phy_id ) ) {
            g_trex.run_in_master();
            delay(1);
        }else{
            g_trex.run_in_core( lpsock->thread_phy_to_virt( phy_id ) );
        }
    }
    return 0;
}



COLD_FUNC uint32_t get_cores_mask(uint32_t cores,int offset){
    int i;

    uint32_t res=1;

    uint32_t mask=(1<<(offset+1));
    for (i=0; i<(cores-1); i++) {
        res |= mask ;
        mask = mask <<1;
    }
    return (res);
}


static char *g_exe_name;
COLD_FUNC const char *get_exe_name() {
    return g_exe_name;
}


COLD_FUNC int main(int argc , char * argv[]){
    g_exe_name = argv[0];

    return ( main_test(argc , argv));
}


COLD_FUNC int update_global_info_from_platform_file(){

    CPlatformYamlInfo *cg=&global_platform_cfg_info;
    CParserOption *g_opts = &CGlobalInfo::m_options;

    CGlobalInfo::m_socket.Create(&cg->m_platform);


    if (!cg->m_info_exist) {
        /* nothing to do ! */
        return 0;
    }

    g_opts->prefix =cg->m_prefix;
    g_opts->preview.setCores(cg->m_thread_per_dual_if);
    if ( cg->m_is_lowend ) {
        g_opts->m_is_lowend = true;
        g_opts->m_is_sleepy_scheduler = true;
        g_opts->m_is_queuefull_retry = false;
    }
    if ( cg->m_stack_type.size() ) {
        g_opts->m_stack_type = cg->m_stack_type;
    }
    #ifdef TREX_PERF
    g_opts->m_is_sleepy_scheduler = true;
    g_opts->m_is_queuefull_retry = false;
    #endif

    if ( cg->m_port_limit_exist ){
        if (cg->m_port_limit > cg->m_if_list.size() ) {
            cg->m_port_limit = cg->m_if_list.size();
        }
        g_opts->m_expected_portd = cg->m_port_limit;
    }else{
        g_opts->m_expected_portd = cg->m_if_list.size();
    }

    if ( g_opts->m_expected_portd < 2 ){
        printf("ERROR need at least 2 ports \n");
        exit(-1);
    }


    if ( cg->m_enable_zmq_pub_exist ){
        g_opts->preview.set_zmq_publish_enable(cg->m_enable_zmq_pub);
        g_opts->m_zmq_port = cg->m_zmq_pub_port;
    }
    if ( cg->m_telnet_exist ){
        g_opts->m_telnet_port = cg->m_telnet_port;
    }

    if ( cg->m_mac_info_exist ){
        int i;
        /* cop the file info */

        int port_size=cg->m_mac_info.size();

        if ( port_size > TREX_MAX_PORTS ){
            port_size = TREX_MAX_PORTS;
        }
        for (i=0; i<port_size; i++){
            cg->m_mac_info[i].copy_src(( char *)g_opts->m_mac_addr[i].u.m_mac.src)   ;
            cg->m_mac_info[i].copy_dest(( char *)g_opts->m_mac_addr[i].u.m_mac.dest)  ;
            g_opts->m_mac_addr[i].u.m_mac.is_set = 1;

            g_opts->m_ip_cfg[i].set_def_gw(cg->m_mac_info[i].get_def_gw());
            g_opts->m_ip_cfg[i].set_ip(cg->m_mac_info[i].get_ip());
            g_opts->m_ip_cfg[i].set_mask(cg->m_mac_info[i].get_mask());
            g_opts->m_ip_cfg[i].set_vlan(cg->m_mac_info[i].get_vlan());
            // If one of the ports has vlan, work in vlan mode
            if (cg->m_mac_info[i].get_vlan() != 0) {
                g_opts->preview.set_vlan_mode_verify(CPreviewMode::VLAN_MODE_NORMAL);
            }
        }
    }

    return (0);
}

COLD_FUNC void update_memory_cfg() {
    CPlatformYamlInfo *cg=&global_platform_cfg_info;

    /* mul by interface type */
    float mul=1.0;
    if (cg->m_port_bandwidth_gb<10 || CGlobalInfo::m_options.m_is_lowend) {
        cg->m_port_bandwidth_gb=10.0;
    }

    mul = mul*(float)cg->m_port_bandwidth_gb/10.0;
    mul= mul * (float)CGlobalInfo::m_options.m_expected_portd/2.0;
    mul= mul * CGlobalInfo::m_options.m_mbuf_factor;


    CGlobalInfo::m_memory_cfg.set_pool_cache_size(RTE_MEMPOOL_CACHE_MAX_SIZE);

    CGlobalInfo::m_memory_cfg.set_number_of_dp_cors(
                                                    CGlobalInfo::m_options.get_number_of_dp_cores_needed() );

    CGlobalInfo::m_memory_cfg.set(cg->m_memory,mul);
    if ( CGlobalInfo::m_options.m_active_flows > CGlobalInfo::m_memory_cfg.m_mbuf[MBUF_DP_FLOWS] ) {
        printf("\n");
        printf("ERROR: current configuration has %u flow objects, and you are asking for %u active flows.\n",
                CGlobalInfo::m_memory_cfg.m_mbuf[MBUF_DP_FLOWS], CGlobalInfo::m_options.m_active_flows);
        printf("Either decrease active flows, or increase memory pool.\n");
        printf("For example put in platform config file:\n");
        printf("\n");
        printf(" memory:\n");
        printf("     dp_flows: %u\n", CGlobalInfo::m_options.m_active_flows);
        printf("\n");
        exit(1);
    }
}

COLD_FUNC void check_pdev_vdev_dummy() {
    bool found_vdev = false;
    bool found_pdev = false;
    uint32_t dev_id = 1e6;
    uint8_t if_index = 0;
    CParserOption *g_opts=&CGlobalInfo::m_options;
    for ( std::string &iface : global_platform_cfg_info.m_if_list ) {
        g_opts->m_dummy_port_map[if_index] = false;
        if ( iface == "dummy" ) {
            g_opts->m_dummy_count++;
            g_opts->m_dummy_port_map[if_index] = true;
            CTVPort(if_index).set_dummy();
        } else if ( iface.find("--vdev") != std::string::npos ) {
            found_vdev = true;
        } else if ( iface.find(":") == std::string::npos ) { // not PCI, assume af-packet
            iface = "--vdev=net_af_packet" + std::to_string(dev_id) + ",iface=" + iface;
            if ( getpagesize() == 4096 ) {
                // block size should be multiplication of PAGE_SIZE and frame size
                // frame size should be Jumbo packet size and multiplication of 16
                iface += ",blocksz=593920,framesz=9280,framecnt=256";
            } else {
                printf("WARNING:\n");
                printf("    Could not automatically set AF_PACKET arguments: blocksz, framesz, framecnt.\n");
                printf("    Will not be able to send Jumbo packets.\n");
                printf("    See link below for more details (section \"Other constraints\")\n");
                printf("    https://www.kernel.org/doc/Documentation/networking/packet_mmap.txt\n");
            }
            dev_id++;
            found_vdev = true;
        } else {
            found_pdev = true;
        }
        if_index++;
    }
    if ( found_vdev ) {
        if ( found_pdev ) {
            printf("\n");
            printf("ERROR: both --vdev and another interface type specified in config file.\n");
            printf("\n");
            exit(1);
        } else {
            g_opts->m_is_vdev = true;
        }
    } else if ( !found_pdev ) {
        printf("\n");
        printf("ERROR: should be specified at least one vdev or PCI-based interface in config file.\n");
        printf("\n");
        exit(1);
    } else { // require at least one port in pair (dual-port) is non-dummy
        for ( uint8_t i=0; i<global_platform_cfg_info.m_if_list.size(); i++ ) {
            if ( g_opts->m_dummy_port_map[i] && g_opts->m_dummy_port_map[dual_port_pair(i)] ) {
                printf("ERROR: got dummy pair of interfaces: %u %u.\nAt least one of them should be non-dummy.\n", i, dual_port_pair(i));
                exit(1);
            }
        }
    }

}

 extern "C" COLD_FUNC int eal_cpu_detected(unsigned lcore_id);
// return mask representing available cores
int core_mask_calc() {
    uint32_t mask = 0;
    int lcore_id;

    for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
        if (eal_cpu_detected(lcore_id)) {
            mask |= (1 << lcore_id);
        }
    }

    return mask;
}

// Return number of set bits in i
COLD_FUNC uint32_t num_set_bits(uint32_t i)
{
    i = i - ((i >> 1) & 0x55555555);
    i = (i & 0x33333333) + ((i >> 2) & 0x33333333);
    return (((i + (i >> 4)) & 0x0F0F0F0F) * 0x01010101) >> 24;
}

// sanity check if the cores we want to use really exist
COLD_FUNC int core_mask_sanity(uint32_t wanted_core_mask) {
    uint32_t calc_core_mask = core_mask_calc();
    uint32_t wanted_core_num, calc_core_num;

    wanted_core_num = num_set_bits(wanted_core_mask);
    calc_core_num = num_set_bits(calc_core_mask);

    if (calc_core_num == 1) {
        printf ("Error: You have only 1 core available. Minimum configuration requires 2 cores\n");
        printf("        If you are running on VM, consider adding more cores if possible\n");
        return -1;
    }
    if (wanted_core_num > calc_core_num) {
        printf("Error: You have %d threads available, but you asked for %d threads.\n", calc_core_num, wanted_core_num);
        printf("       Calculation is: -c <num>(%d) * dual ports (%d) + 1 master thread %s"
               , CGlobalInfo::m_options.preview.getCores(), CGlobalInfo::m_options.get_expected_dual_ports()
               , get_is_rx_thread_enabled() ? "+1 latency thread (because of -l flag)\n" : "\n");
        if (CGlobalInfo::m_options.preview.getCores() > 1)
            printf("       Maybe try smaller -c <num>.\n");
        printf("       If you are running on VM, consider adding more cores if possible\n");
        return -1;
    }

    if (wanted_core_mask != (wanted_core_mask & calc_core_mask)) {
        printf ("Serious error: Something is wrong with the hardware. Wanted core mask is %x. Existing core mask is %x\n", wanted_core_mask, calc_core_mask);
        return -1;
    }

    return 0;
}


COLD_FUNC int  update_dpdk_args(void){

    CPlatformSocketInfo * lpsock=&CGlobalInfo::m_socket;
    CParserOption * lpop= &CGlobalInfo::m_options;
    CPlatformYamlInfo *cg=&global_platform_cfg_info;

    lpsock->set_rx_thread_is_enabled(get_is_rx_thread_enabled());
    lpsock->set_number_of_threads_per_ports(lpop->preview.getCores() );
    lpsock->set_number_of_dual_ports(lpop->get_expected_dual_ports());
    if ( !lpsock->sanity_check() ){
        printf(" ERROR in configuration file \n");
        return (-1);
    }

    if ( isVerbose(0)  ) {
        lpsock->dump(stdout);
    }

    if ( !CGlobalInfo::m_options.m_is_vdev ){
        std::string err;
        if ( port_map.set_cfg_input(cg->m_if_list,err)!= 0){
            printf("%s \n",err.c_str());
            return(-1);
        }
    }

    /* set the DPDK options */
    g_dpdk_args_num = 0;
    #define SET_ARGS(val) { g_dpdk_args[g_dpdk_args_num++] = (char *)(val); }

    SET_ARGS((char *)"xx");
    CPreviewMode *lpp=&CGlobalInfo::m_options.preview;

    if ( lpp->get_ntacc_so_mode() ){
        std::string &ntacc_so_str = get_ntacc_so_string();
        ntacc_so_str = "libntacc-64" + std::string(g_image_postfix) + ".so";
        SET_ARGS("-d");
        SET_ARGS(ntacc_so_str.c_str());
    }

    if ( lpp->get_mlx5_so_mode() ){
        std::string &mlx5_so_str = get_mlx5_so_string();
        mlx5_so_str = "libmlx5-64" + std::string(g_image_postfix) + ".so";
        SET_ARGS("-d");
        SET_ARGS(mlx5_so_str.c_str());
    }

    if ( lpp->get_mlx4_so_mode() ){
        std::string &mlx4_so_str = get_mlx4_so_string();
        mlx4_so_str = "libmlx4-64" + std::string(g_image_postfix) + ".so";
        SET_ARGS("-d");
        SET_ARGS(mlx4_so_str.c_str());
    }

    if ( CGlobalInfo::m_options.m_is_lowend ) { // assign all threads to core 0
        g_cores_str[0] = '(';
        lpsock->get_cores_list(g_cores_str + 1);
        strcat(g_cores_str, ")@0");
        SET_ARGS("--lcores");
        SET_ARGS(g_cores_str);
    } else {
        snprintf(g_cores_str, sizeof(g_cores_str), "0x%llx" ,(unsigned long long)lpsock->get_cores_mask());
        if (core_mask_sanity(strtol(g_cores_str, NULL, 16)) < 0) {
            return -1;
        }
        SET_ARGS("-c");
        SET_ARGS(g_cores_str);
    }

    SET_ARGS("-n");
    SET_ARGS("4");

    if ( lpp->getVMode() == 0  ) {
        SET_ARGS("--log-level");
        snprintf(g_loglevel_str, sizeof(g_loglevel_str), "%d", 4);
        SET_ARGS(g_loglevel_str);
    }else{
        SET_ARGS("--log-level");
        snprintf(g_loglevel_str, sizeof(g_loglevel_str), "%d", lpp->getVMode()+1);
        SET_ARGS(g_loglevel_str);
    }

    SET_ARGS("--master-lcore");

    snprintf(g_master_id_str, sizeof(g_master_id_str), "%u", lpsock->get_master_phy_id());
    SET_ARGS(g_master_id_str);

    /* add white list */
    if ( CGlobalInfo::m_options.m_is_vdev ) {
        for ( std::string &iface : cg->m_if_list ) {
            if ( iface != "dummy" ) {
                SET_ARGS(iface.c_str());
            }
        }
        SET_ARGS("--no-pci");
        SET_ARGS("--no-huge");
        std::string mem_str;
        SET_ARGS("-m");
        if ( cg->m_limit_memory.size() ) {
            mem_str = cg->m_limit_memory;
        } else if ( CGlobalInfo::m_options.m_is_lowend ) {
            mem_str = std::to_string(50 + 100 * cg->m_if_list.size());
        } else {
            mem_str = "1024";
        }
        snprintf(g_socket_mem_str, sizeof(g_socket_mem_str), "%s", mem_str.c_str());
        SET_ARGS(g_socket_mem_str);
    } else {
        dpdk_input_args_t & dif = *port_map.get_dpdk_input_args();

        for (int i=0; i<(int)dif.size(); i++) {
            if ( dif[i] != "dummy" ) {
                SET_ARGS("-w");
                SET_ARGS(dif[i].c_str());
            }
        }
    }

    SET_ARGS("--legacy-mem");

    if ( lpop->prefix.length() ) {
        SET_ARGS("--file-prefix");
        snprintf(g_prefix_str, sizeof(g_prefix_str), "%s", lpop->prefix.c_str());
        SET_ARGS(g_prefix_str);
    }

    if( lpop->prefix.length() or cg->m_limit_memory.length() ) {
        if ( !CGlobalInfo::m_options.m_is_lowend && !CGlobalInfo::m_options.m_is_vdev ) {
            SET_ARGS("--socket-mem");
            char *mem_str;
            if (cg->m_limit_memory.length()) {
                mem_str = (char *)cg->m_limit_memory.c_str();
            }else{
                mem_str = (char *)"1024";
            }
            int pos = snprintf(g_socket_mem_str, sizeof(g_socket_mem_str), "%s", mem_str);
            for (int socket = 1; socket < MAX_SOCKETS_SUPPORTED; socket++) {
                char path[PATH_MAX];
                snprintf(path, sizeof(path), "/sys/devices/system/node/node%u/", socket);
                if (access(path, F_OK) == 0) {
                    pos += snprintf(g_socket_mem_str+pos, sizeof(g_socket_mem_str)-pos, ",%s", mem_str);
                } else {
                    break;
                }
            }
            SET_ARGS(g_socket_mem_str);
        }
    }

    /* dpdk extenstion */
    for (std::string &opts : cg->m_ext_dpdk) {
        SET_ARGS(opts.c_str());
    }

    if ( lpp->getVMode() > 0  ) {
        printf("DPDK args \n");
        int i;
        for (i=0; i<g_dpdk_args_num; i++) {
            printf(" %s ",g_dpdk_args[i]);
        }
        printf(" \n ");
    }
    return (0);
}


COLD_FUNC int sim_load_list_of_cap_files(CParserOption * op){

    CFlowGenList fl;
    fl.Create();
    fl.load_from_yaml(op->cfg_file,1);
    if ( op->preview.getVMode() >0 ) {
        fl.DumpCsv(stdout);
    }
    uint32_t start=    os_get_time_msec();

    CErfIF erf_vif;

    fl.generate_p_thread_info(1);
    CFlowGenListPerThread   * lpt;
    lpt=fl.m_threads_info[0];
    lpt->set_vif(&erf_vif);

    if ( (op->preview.getVMode() >1)  || op->preview.getFileWrite() ) {
        lpt->start_sim(op->out_file,op->preview);
    }

    lpt->m_node_gen.DumpHist(stdout);

    uint32_t stop=    os_get_time_msec();
    printf(" d time = %ul %ul \n",stop-start,os_get_time_freq());
    fl.Delete();
    return (0);
}

COLD_FUNC void dump_interfaces_info() {
    printf("Showing interfaces info.\n");
    uint8_t m_max_ports = rte_eth_dev_count();
    struct ether_addr mac_addr;
    char mac_str[ETHER_ADDR_FMT_SIZE];
    struct rte_eth_dev_info dev_info;
    struct rte_pci_device pci_dev;

    for (uint8_t port_id=0; port_id<m_max_ports; port_id++) {
        // PCI, MAC and Driver
        rte_eth_dev_info_get(port_id, &dev_info);
        rte_eth_macaddr_get(port_id, &mac_addr);
        ether_format_addr(mac_str, sizeof mac_str, &mac_addr);
        bool ret = fill_pci_dev(&dev_info, &pci_dev);
        if ( ret ) {
            struct rte_pci_addr *pci_addr = &pci_dev.addr;
            printf("PCI: %04x:%02x:%02x.%d", pci_addr->domain, pci_addr->bus, pci_addr->devid, pci_addr->function);
        } else {
            printf("PCI: N/A");
        }
        printf(" - MAC: %s - Driver: %s\n", mac_str, dev_info.driver_name);
    }
}


COLD_FUNC int learn_image_postfix(char * image_name){

    char *p = strstr(image_name,TREX_NAME);
    if (p) {
        strcpy(g_image_postfix,p+strlen(TREX_NAME));
    }
    return(0);
}

COLD_FUNC int main_test(int argc , char * argv[]){

    learn_image_postfix(argv[0]);

    int ret;
    unsigned lcore_id;
    
    if (TrexBuildInfo::is_sanitized()) {
         printf("\n*******************************************************\n");
         printf("\n***** Sanitized binary - Expect lower performance *****\n\n");
         printf("\n*******************************************************\n");
    }

    CParserOption * po=&CGlobalInfo::m_options;

    printf("Starting  TRex %s please wait  ... \n",VERSION_BUILD_NUM);

    po->preview.clean();

    if ( parse_options_wrapper(argc, argv, true ) != 0){
        exit(-1);
    }

    if (!po->preview.get_is_termio_disabled()) {
        utl_termio_init();
    }

    /* set line buffered mode only if --iom 0 */
    if (CGlobalInfo::m_options.m_io_mode == 0) {
        setvbuf(stdout, NULL, _IOLBF, 0);
    }


    /* enable core dump if requested */
    if (po->preview.getCoreDumpEnable()) {
        utl_set_coredump_size(-1);
    }
    else {
        utl_set_coredump_size(0);
    }


    update_global_info_from_platform_file();

    /* It is not a mistake. Give the user higher priorty over the configuration file */
    if (parse_options_wrapper(argc, argv, false) != 0) {
        exit(-1);
    }


    update_memory_cfg();

    if ( po->preview.getVMode() > 0){
        po->dump(stdout);
        CGlobalInfo::m_memory_cfg.Dump(stdout);
    }

    check_pdev_vdev_dummy();

    if (update_dpdk_args() < 0) {
        return -1;
    }

    if ( po->preview.getVMode() == 0  ) {
        rte_log_set_global_level(1);
    }

    uid_t uid;
    uid = geteuid ();
    if ( uid != 0 ) {
        printf("ERROR you must run with superuser priviliges \n");
        printf("User id   : %d \n",uid);
        printf("try 'sudo' %s \n",argv[0]);
        return (-1);
    }

    if ( get_is_tcp_mode() ){

        if ( po->preview.get_is_rx_check_enable() ){
           printf("ERROR advanced stateful does not require --rx-check mode, it is done by default, please remove this switch\n");
           return (-1);
        }

        /* set latency to work in ICMP mode with learn mode */
        po->m_learn_mode = CParserOption::LEARN_MODE_IP_OPTION;
        if (po->m_l_pkt_mode ==0){
            po->m_l_pkt_mode =L_PKT_SUBMODE_REPLY;
        }

        if ( po->preview.getClientServerFlip() ){
            printf("ERROR advanced stateful does not support --flip option, please remove this switch\n");
            return (-1);
        }

        if ( po->preview.getClientServerFlowFlip() ){
            printf("ERROR advanced stateful does not support -p option, please remove this switch\n");
            return (-1);
        }

        if ( po->preview.getClientServerFlowFlipAddr() ){
            printf("ERROR advanced stateful does not support -e option, please remove this switch\n");
            return (-1);
        }

        if ( po->m_active_flows ){
            printf("ERROR advanced stateful does not support --active-flows option, please remove this switch  \n");
            return (-1);
        }
    }

    /* set affinity to the master core as default */
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(CGlobalInfo::m_socket.get_master_phy_id(), &mask);
    pthread_setaffinity_np(pthread_self(), sizeof(mask), &mask);

    ret = rte_eal_init(g_dpdk_args_num, (char **)g_dpdk_args);
    if (ret < 0){
        printf(" You might need to run ./trex-cfg  once  \n");
        rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
    }
    if (get_op_mode() == OP_MODE_DUMP_INTERFACES) {
        dump_interfaces_info();
        exit(0);
    }
    reorder_dpdk_ports();
    set_driver();

    uint32_t driver_cap = get_ex_drv()->get_capabilities();
    
    int res;
    res =CGlobalInfo::m_dpdk_mode.choose_mode((trex_driver_cap_t)driver_cap);
    if (res == tmDPDK_UNSUPPORTED) {
        exit(1);
    }

    time_init();

    /* check if we are in simulation mode */
    if ( CGlobalInfo::m_options.out_file != "" ){
        printf(" t-rex simulation mode into %s \n",CGlobalInfo::m_options.out_file.c_str());
        return ( sim_load_list_of_cap_files(&CGlobalInfo::m_options) );
    }

    if ( !g_trex.Create() ){
        exit(1);
    }

    if (po->preview.get_is_rx_check_enable() &&  (po->m_rx_check_sample< get_min_sample_rate()) ) {
        po->m_rx_check_sample = get_min_sample_rate();
        printf("Warning:rx check sample rate should not be lower than %d. Setting it to %d\n",get_min_sample_rate(),get_min_sample_rate());
    }

    /* set dump mode */
    g_trex.m_io_modes.set_mode((CTrexGlobalIoMode::CliDumpMode)CGlobalInfo::m_options.m_io_mode);

    /* disable WD if needed */
    bool wd_enable = (CGlobalInfo::m_options.preview.getWDDisable() ? false : true);
    TrexWatchDog::getInstance().init(wd_enable);

    // For unit testing of HW rules and queues configuration. Just send some packets and exit.
    if (CGlobalInfo::m_options.m_debug_pkt_proto != 0) {
        CTrexDpdkParams dpdk_p;
        get_dpdk_drv_params(dpdk_p);
        CTrexDebug debug = CTrexDebug(g_trex.m_ports[0], g_trex.m_max_ports
                                      , dpdk_p.get_total_rx_queues());
        int ret;

        if (CGlobalInfo::m_options.m_debug_pkt_proto == D_PKT_TYPE_HW_TOGGLE_TEST) {
            // Unit test: toggle many times between receive all and stateless/stateful modes,
            // to test resiliency of add/delete fdir filters
            printf("Starting receive all/normal mode toggle unit test\n");
            for (int i = 0; i < 100; i++) {
                for (int port_id = 0; port_id < g_trex.m_max_ports; port_id++) {
                    CPhyEthIF *pif = g_trex.m_ports[port_id];
                    pif->set_port_rcv_all(true);
                }
                ret = debug.test_send(D_PKT_TYPE_HW_VERIFY_RCV_ALL);
                if (ret != 0) {
                    printf("Iteration %d: Receive all mode failed\n", i);
                    exit(ret);
                }

                for (int port_id = 0; port_id < g_trex.m_max_ports; port_id++) {
                    CPhyEthIF *pif = g_trex.m_ports[port_id];
                    get_ex_drv()->configure_rx_filter_rules(pif);
                }

                ret = debug.test_send(D_PKT_TYPE_HW_VERIFY);
                if (ret != 0) {
                    printf("Iteration %d: Normal mode failed\n", i);
                    exit(ret);
                }

                printf("Iteration %d OK\n", i);
            }
            exit(0);
        } else {
            if (CGlobalInfo::m_options.m_debug_pkt_proto == D_PKT_TYPE_HW_VERIFY_RCV_ALL) {
                for (int port_id = 0; port_id < g_trex.m_max_ports; port_id++) {
                    CPhyEthIF *pif = g_trex.m_ports[port_id];
                    pif->set_port_rcv_all(true);
                }
            }
            ret = debug.test_send(CGlobalInfo::m_options.m_debug_pkt_proto);
            exit(ret);
        }
    }

    // in case of client config, we already run pretest
    if (! CGlobalInfo::m_options.preview.get_is_client_cfg_enable()) {
        g_trex.pre_test();
    }

    // after doing all needed ARP resolution, we need to flush queues, and stop our drop queue
    g_trex.device_rx_queue_flush();
    for (int i = 0; i < g_trex.m_max_ports; i++) {
        CPhyEthIF *_if = g_trex.m_ports[i];
        _if->stop_rx_drop_queue();
    }

    if ( CGlobalInfo::m_options.is_latency_enabled()
         && (CGlobalInfo::m_options.m_latency_prev > 0)) {
        uint32_t pkts = CGlobalInfo::m_options.m_latency_prev *
            CGlobalInfo::m_options.m_latency_rate;
        printf("Starting warm up phase for %d sec\n",CGlobalInfo::m_options.m_latency_prev);
        g_trex.m_mg.start(pkts, NULL);
        delay(CGlobalInfo::m_options.m_latency_prev* 1000);
        printf("Finished \n");
        g_trex.m_mg.reset();
    }

    if ( CGlobalInfo::m_options.preview.getOnlyLatency() ){
        rte_eal_mp_remote_launch(latency_one_lcore, NULL, CALL_MASTER);
        RTE_LCORE_FOREACH_SLAVE(lcore_id) {
            if (rte_eal_wait_lcore(lcore_id) < 0)
                return -1;
        }
        g_trex.stop_master();

        return (0);
    }

    if ( CGlobalInfo::m_options.preview.getSingleCore() ) {
        g_trex.run_in_core(1);
        g_trex.stop_master();
        return (0);
    }

    rte_eal_mp_remote_launch(slave_one_lcore, NULL, CALL_MASTER);
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        if (rte_eal_wait_lcore(lcore_id) < 0)
            return -1;
    }

    g_trex.stop_master();
    g_trex.Delete();
    
    if (!CGlobalInfo::m_options.preview.get_is_termio_disabled()) {
        utl_termio_reset();
    }

    return (0);
}

COLD_FUNC void wait_x_sec(int sec) {
    int i;
    printf(" wait %d sec ", sec);
    fflush(stdout);
    for (i=0; i<sec; i++) {
        delay(1000);
        printf(".");
        fflush(stdout);
    }
    printf("\n");
    fflush(stdout);
}

#define TCP_UDP_OFFLOAD (DEV_TX_OFFLOAD_IPV4_CKSUM |DEV_TX_OFFLOAD_UDP_CKSUM | DEV_TX_OFFLOAD_TCP_CKSUM)

/* should be called after rte_eal_init() */
COLD_FUNC void set_driver() {
    uint8_t m_max_ports;
    if ( CGlobalInfo::m_options.m_is_vdev ) {
        m_max_ports = rte_eth_dev_count() + CGlobalInfo::m_options.m_dummy_count;
    } else {
        m_max_ports = port_map.get_max_num_ports();
    }

    if ( m_max_ports != CGlobalInfo::m_options.m_expected_portd ) {
        printf("Could not find all interfaces (asked for: %u, found: %u).\n", CGlobalInfo::m_options.m_expected_portd, m_max_ports);
        exit(1);
    }
    struct rte_eth_dev_info dev_info;
    for (int i=0; i<m_max_ports; i++) {
        CTVPort ctvport = CTVPort(i);
        if ( !ctvport.is_dummy() ) {
            rte_eth_dev_info_get(ctvport.get_repid(), &dev_info);
            break;
        }
    }

    if ( !CTRexExtendedDriverDb::Ins()->is_driver_exists(dev_info.driver_name) ){
        printf("\nError: driver %s is not supported. Please consult the documentation for a list of supported drivers\n"
               ,dev_info.driver_name);
        exit(1);
    }

    CTRexExtendedDriverDb::Ins()->set_driver_name(dev_info.driver_name);

    if ( CGlobalInfo::m_options.m_dummy_count ) {
        CTRexExtendedDriverDb::Ins()->create_dummy();
    }

    bool cs_offload=false;
    CPreviewMode * lp=&CGlobalInfo::m_options.preview;

    printf(" driver capability  :");
    if ( (dev_info.tx_offload_capa & TCP_UDP_OFFLOAD) == TCP_UDP_OFFLOAD ){
        cs_offload=true;
        printf(" TCP_UDP_OFFLOAD ");
    }

    if ( (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_TCP_TSO) == DEV_TX_OFFLOAD_TCP_TSO ){
        printf(" TSO ");
        lp->set_dev_tso_support(true);
    }
    printf("\n");

    if (lp->getTsoOffloadDisable() && lp->get_dev_tso_support()){
        printf("Warning TSO is supported and asked to be disabled by user \n");
        lp->set_dev_tso_support(false);
    }


    if (cs_offload) {
        if (lp->getChecksumOffloadEnable()) {
            printf("Warning --checksum-offload is turn on by default, no need to call it \n");
        }

        if (lp->getChecksumOffloadDisable()==false){
            lp->setChecksumOffloadEnable(true);
        }else{
            printf("checksum-offload disabled by user \n");
        }
    }

    
}



/*

 map requested ports to rte_eth scan

*/
COLD_FUNC void reorder_dpdk_ports() {

    CTRexPortMapper * lp=CTRexPortMapper::Ins();

    CPlatformYamlInfo *cg=&global_platform_cfg_info;

    if ( cg->m_if_list_vdevs.size()  > 0 ) {
        if ( isVerbose(0) ){
           printf(" size of interfaces_vdevs %d",cg->m_if_list_vdevs.size());
        }
        int if_index = 0;
        for (std::string &opts : cg->m_if_list_vdevs) {
            uint16_t port_id;
            int ret = rte_eth_dev_get_port_by_name((const char *)opts.c_str(), &port_id);
        	if (ret) {
                 printf("Failed to find  %s in DPDK vdev ", opts.c_str());
                 dump_dpdk_devices();
                 exit(1);
	        }
            if ( isVerbose(0) ){
                printf(" ===>>>found %s %d \n",opts.c_str(),port_id);
            }
            lp->set_map(if_index,port_id);
            if_index++;
        }
        return;
    }
   
    if ( CGlobalInfo::m_options.m_is_vdev ) {
        uint8_t if_index = 0;
        for (int i=0; i<global_platform_cfg_info.m_if_list.size(); i++) {
            if ( CTVPort(i).is_dummy() ) {
                continue;
            }
            lp->set_map(i, if_index);
            if_index++;
        }
        return;
    }

    #define BUF_MAX 200
    char buf[BUF_MAX];
    dpdk_input_args_t  dpdk_scan;
    dpdk_map_args_t res_map;

    std::string err;

    /* build list of dpdk devices */
    uint8_t cnt = rte_eth_dev_count();
    int i;
    for (i=0; i<cnt; i++) {
        if (rte_eth_dev_pci_addr((repid_t)i,buf,BUF_MAX)!=0){
            printf("Failed mapping TRex port id to DPDK id: %d\n", i);
            exit(1);
        }
        dpdk_scan.push_back(std::string(buf));
    }

    if ( port_map.get_map_args(dpdk_scan, res_map, err) != 0){
        printf("ERROR in DPDK map \n");
        printf("%s\n",err.c_str());
        exit(1);
    }

    /* update MAP */
    lp->set(cnt, res_map);

    if ( isVerbose(0) ){
        port_map.dump(stdout);
        lp->Dump(stdout);
    }
}


#if 0  
/**
 * convert chain of mbuf to one big mbuf
 *
 * @param m
 *
 * @return
 */
struct rte_mbuf *  rte_mbuf_convert_to_one_seg(struct rte_mbuf *m){
    unsigned int len;
    struct rte_mbuf * r;
    struct rte_mbuf * old_m;
    old_m=m;

    len=rte_pktmbuf_pkt_len(m);
    /* allocate one big mbuf*/
    r = CGlobalInfo::pktmbuf_alloc(0,len);
    assert(r);
    if (r==0) {
        rte_pktmbuf_free(m);
        return(r);
    }
    char *p=rte_pktmbuf_append(r,len);

    while ( m ) {
        len = m->data_len;
        assert(len);
        memcpy(p,(char *)m->buf_addr, len);
        p+=len;
        m = m->next;
    }
    rte_pktmbuf_free(old_m);
    return(r);
}
#endif

/**
 * DPDK API target
 */
TrexPlatformApi &get_platform_api() {
    static TrexDpdkPlatformApi api;
    
    return api;
}
