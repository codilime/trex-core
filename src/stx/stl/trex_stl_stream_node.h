/*
 Itay Marom
 Hanoh Haim
 Cisco Systems, Inc.
*/

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
#ifndef __TREX_STL_STREAM_NODE_H__
#define __TREX_STL_STREAM_NODE_H__


#include <stdio.h>

#include <common/Network/Packet/PTPPacket.h>
#include <common/Network/Packet/EthernetHeader.h>
#include <common/Network/Packet/IPHeader.h>
#include <common/Network/Packet/UdpHeader.h>

#include "bp_sim.h"
#include "trex_stl_stream.h"

class TrexStatelessDpCore;
class TrexStatelessDpPerPort;



class TrexCpToDpMsgBase;
class CFlowGenListPerThread;


struct CGenNodeCacheMbuf {
    rte_mbuf_t *  m_mbuf_const;
    rte_mbuf_t *  m_array[0];
public:
    static uint32_t get_object_size(uint32_t size){
        return ( sizeof(CGenNodeCacheMbuf) + sizeof(rte_mbuf_t *) * size );
    }
};

/* this is a event for stateless */
struct CGenNodeStateless : public CGenNodeBase  {
friend class TrexStatelessDpCore;

public:

    /* flags MASKS*/
    enum {
        SL_NODE_FLAGS_DIR                  =1, //USED by master
        SL_NODE_FLAGS_MBUF_CACHE           =2, //USED by master

        SL_NODE_CONST_MBUF                 =4,
                                             
        SL_NODE_VAR_PKT_SIZE               = 8,
        SL_NODE_STATS_NEEDED               = 0x10,
        SL_NODE_CONST_MBUF_CACHE_ARRAY     = 0x20  /* array of mbuf - cache */
    };

    enum {                                          
            ss_FREE_RESUSE =1, /* should be free by scheduler */
            ss_INACTIVE    =2, /* will be active by other stream or stopped */
            ss_ACTIVE      =3  /* the stream is active */ 
         };
    typedef uint8_t stream_state_t ;

    static std::string get_stream_state_str(stream_state_t stream_state);

private:
    /******************************/
    /* cache line 0               */
    /* important stuff here  R/W  */
    /******************************/
    void *              m_cache_mbuf; /* could be an array or a one mbuf */

    double              m_next_time_offset; /* in sec */
    uint32_t            m_action_counter;
    uint16_t            m_stat_hw_id; // hw id used to count rx and tx stats
    uint16_t            m_cache_array_cnt;

    uint8_t             m_null_stream;
    stream_state_t      m_state;
    uint8_t             m_stream_type; /* see TrexStream::STREAM_TYPE ,stream_type_t */
    uint8_t             m_pause;

    uint32_t            m_single_burst; /* the number of bursts in case of burst */
    uint32_t            m_single_burst_refill; 

    uint32_t            m_multi_bursts; /* in case of multi_burst how many bursts */
    double              m_next_time_offset_backup; /* paused nodes will be given slower ipg, backup value */

    /******************************/
    /* cache line 1  
      this cache line should be READONLY ! you can write only at init time */ 
    /******************************/
    TrexStream *         m_ref_stream_info; /* the stream info */
    CGenNodeStateless  * m_next_stream;

    uint8_t *            m_original_packet_data_prefix; /* pointer to the original first pointer 64/128/512 */

    /* Fast Field VM section */
    uint8_t *            m_vm_flow_var; /* pointer to the vm flow var */
    uint8_t *            m_vm_program;  /* pointer to the program */
    uint16_t             m_vm_program_size; /* up to 64K op codes */
    uint16_t             m_cache_size;   /*RO*/ /* the size of the mbuf array */
    uint8_t              m_batch_size;   /*RO*/ /* the batch size */
    uint8_t              m_pad5;
    uint32_t             m_profile_id;

    uint16_t             m_pad6; 

    /* End Fast Field VM Section */

    /* pad to match the size of CGenNode */
    uint8_t             m_pad_end[8];

    /* CACHE_LINE */
    uint64_t            m_pad3[8];


public:

    uint32_t            get_profile_id() {
        return (m_profile_id);
    }

    /**
     * calculate the time offset based 
     * on the PPS and multiplier 
     * 
     */
    void update_rate(double factor) {
        /* update the inter packet gap */
        m_next_time_offset_backup /= factor;
        if ( likely(!m_pause) ) {
            m_next_time_offset = m_next_time_offset_backup;
        }
    }

    void set_ipg(double ipg) {
        /* set inter packet gap */
        m_next_time_offset_backup = ipg;
        if ( likely(!m_pause) ) {
            m_next_time_offset = m_next_time_offset_backup;
        }
    }

    /* we restart the stream, schedule it using stream isg */
    inline void update_refresh_time(double cur_time){
        m_time = cur_time + usec_to_sec(m_ref_stream_info->m_isg_usec) + m_ref_stream_info->m_mc_phase_pre_sec;
    }

    inline bool is_mask_for_free(){
        return (get_state() == CGenNodeStateless::ss_FREE_RESUSE ?true:false);

    }
    inline void mark_for_free(){
        if (m_state != CGenNodeStateless::ss_FREE_RESUSE) {
            /* must be first */
            free_stl_node();
            set_state(CGenNodeStateless::ss_FREE_RESUSE);
            /* only to be safe */
            m_ref_stream_info= NULL;
            m_next_stream= NULL;
        }
    }

    bool is_pause(){
        return (m_pause==1?true:false);
    }

    void set_pause(bool enable){
        if ( enable ){
            m_next_time_offset = 0.1; // we don't want paused nodes to interfere too much in scheduler with non-paused
            m_pause=1;
        }else{
            m_next_time_offset = m_next_time_offset_backup;
            m_pause=0;
        }
    }

    bool is_node_active() {
        /* bitwise or - faster instead of two IFs */
        return ((m_pause | m_null_stream) == 0);
    }

    inline uint8_t  get_stream_type(){
        return (m_stream_type);
    }

    inline uint32_t   get_single_burst_cnt(){
        return (m_single_burst);
    }

    inline double   get_multi_ibg_sec(){
        return (usec_to_sec(m_ref_stream_info->m_ibg_usec));
    }

    inline uint32_t   get_multi_burst_cnt(){
        return (m_multi_bursts);
    }

    inline  void set_state(stream_state_t new_state){
        m_state=new_state;
    }


    inline stream_state_t get_state() {
        return m_state;
    }

    void refresh();

    inline void handle_continues(CFlowGenListPerThread *thread) {

        if (likely (is_node_active())) {
            thread->m_node_gen.m_v_if->send_node( (CGenNode *)this);
        }

        /* in case of continues */
        m_time += m_next_time_offset;

        /* insert a new event */
        thread->m_node_gen.m_p_queue.push( (CGenNode *)this);
    }

    inline void handle_multi_burst(CFlowGenListPerThread *thread) {
        if (likely (is_node_active())) {
            thread->m_node_gen.m_v_if->send_node( (CGenNode *)this);
        }

        m_single_burst--;
        if (m_single_burst > 0 ) {
            /* in case of continues */
            m_time += m_next_time_offset;

            thread->m_node_gen.m_p_queue.push( (CGenNode *)this);
        }else{
            m_multi_bursts--;
            if ( m_multi_bursts == 0 ) {
                set_state(CGenNodeStateless::ss_INACTIVE);
                
                TrexStatelessDpCore *stl_dp_core = (TrexStatelessDpCore *)thread->get_dp_core();
                if ( stl_dp_core->set_stateless_next_node(this, m_next_stream) ) {
                    /* update the next stream time using isg and post phase */
                    m_next_stream->update_refresh_time(m_time + m_ref_stream_info->get_next_stream_delay_sec());

                    thread->m_node_gen.m_p_queue.push( (CGenNode *)m_next_stream);
                }else{
                    // in case of zero we will schedule a command to stop 
                    // will be called from set_stateless_next_node
                }

            }else{
                /* next burst is like starting a new stream - add pre and post phase */
                m_time +=  m_ref_stream_info->get_next_burst_delay_sec();
                m_single_burst = m_single_burst_refill;
                thread->m_node_gen.m_p_queue.push( (CGenNode *)this);
            }
        }
    }

        
    /**
     * main function to handle an event of a packet tx
     * 
     * 
     * 
     */

    inline void handle(CFlowGenListPerThread *thread) {

        if (m_stream_type == TrexStream::stCONTINUOUS ) {
            handle_continues(thread) ;
        }else{
            if (m_stream_type == TrexStream::stMULTI_BURST) {
                handle_multi_burst(thread);
            }else{
                assert(0);
            }
        }

    }

    void set_socket_id(socket_id_t socket){
        m_socket_id=socket;
    }

    socket_id_t get_socket_id(){
        return ( m_socket_id );
    }

    void set_stat_hw_id(uint16_t hw_id) {
        m_stat_hw_id = hw_id;
    }

    uint16_t get_stat_hw_id() {
        return ( m_stat_hw_id );
    }

    inline void set_stat_needed() {
        m_flags |= SL_NODE_STATS_NEEDED;
    }

    inline bool is_stat_needed() {
        return ((m_flags & SL_NODE_STATS_NEEDED) != 0);
    }

    inline bool is_latency_stream() {
        return m_ref_stream_info->is_latency_stream();
    }

    inline void set_mbuf_cache_dir(pkt_dir_t  dir){
        if (dir) {
            m_flags |=NODE_FLAGS_DIR;
        }else{
            m_flags &=~NODE_FLAGS_DIR;
        }
    }

    inline pkt_dir_t get_mbuf_cache_dir(){
        return ((pkt_dir_t)( m_flags &1));
    }

    inline void set_cache_mbuf(rte_mbuf_t * m){
        m_cache_mbuf=(void *)m;
        m_flags |= NODE_FLAGS_MBUF_CACHE;
    }

    inline rte_mbuf_t * get_cache_mbuf(){
        if ( m_flags & NODE_FLAGS_MBUF_CACHE ) {
            return ((rte_mbuf_t *)m_cache_mbuf);
        }else{
            return ((rte_mbuf_t *)0);
        }
    }

    inline void set_var_pkt_size(){
        m_flags |= SL_NODE_VAR_PKT_SIZE;
    }

    inline bool is_var_pkt_size(){
        return ( ( m_flags &SL_NODE_VAR_PKT_SIZE )?true:false);
    }

    inline void set_const_mbuf(rte_mbuf_t * m){
        m_cache_mbuf=(void *)m;
        m_flags |= SL_NODE_CONST_MBUF;
    }

    inline rte_mbuf_t * get_const_mbuf(){
        if ( m_flags &SL_NODE_CONST_MBUF ) {
            return ((rte_mbuf_t *)m_cache_mbuf);
        }else{
            return ((rte_mbuf_t *)0);
        }
    }

    void clear_const_mbuf(){
        m_flags= ( m_flags & ~SL_NODE_CONST_MBUF );
    }

    /* prefix header exits only in non cache mode size is 64/128/512  other are not possible right now */
    inline void alloc_prefix_header(uint16_t size){
         set_prefix_header_size(size);
         m_original_packet_data_prefix = (uint8_t *)malloc(size);
         assert(m_original_packet_data_prefix);
    }

    inline void free_prefix_header(){
         if (m_original_packet_data_prefix) {
             free(m_original_packet_data_prefix);
             m_original_packet_data_prefix=0;
         }
    }

    /* prefix headr could be 64/128/512 */
    inline void set_prefix_header_size(uint16_t size){
        m_src_port=size;
    }

    inline uint16_t prefix_header_size(){
        return (m_src_port);
    }

    rte_mbuf_t   * alloc_flow_stat_mbuf(rte_mbuf_t *m, struct flow_stat_payload_header * &fsp_head
                                        , bool is_const);
    bool alloc_flow_stat_mbuf_test_const();
    rte_mbuf_t   * alloc_node_with_vm();

    void free_stl_node();

protected:

    void free_stl_vm_buf();

public:
    void cache_mbuf_array_init();

    inline bool is_cache_mbuf_array(){
        return  ( m_flags & SL_NODE_CONST_MBUF_CACHE_ARRAY ? true:false );
    }

    void cache_mbuf_array_copy(CGenNodeCacheMbuf *obj,uint16_t size);

     rte_mbuf_t ** cache_mbuf_array_alloc(uint16_t size);

     void cache_mbuf_array_free();

     void cache_mbuf_array_set(uint16_t index,rte_mbuf_t * m);

     void cache_mbuf_array_set_const_mbuf(rte_mbuf_t * m);

     rte_mbuf_t * cache_mbuf_array_get_const_mbuf();

     rte_mbuf_t * cache_mbuf_array_get(uint16_t index);

     rte_mbuf_t * cache_mbuf_array_get_cur(void){
            CGenNodeCacheMbuf *p =(CGenNodeCacheMbuf *) m_cache_mbuf;
            rte_mbuf_t * m=p->m_array[m_cache_array_cnt];
            assert(m);
            m_cache_array_cnt++;
            if (m_cache_array_cnt == m_cache_size) {
                m_cache_array_cnt=0;
            }
            return m;
     }

    inline uint32_t get_user_stream_id(void) {
        return m_ref_stream_info->m_user_stream_id;
    }

public:
    /* debug functions */

    int get_stream_id();

    static void DumpHeader(FILE *fd);

    void Dump(FILE *fd);

private:

    void generate_random_seed();
    void refresh_vm_bss();


    void set_random_seed(uint32_t seed){
        uint32_t *p=get_random_bss_seed_memory();
        *p=seed;
    }

    uint32_t* get_random_bss_seed_memory(){
        return (uint32_t*)m_vm_flow_var;/* always the first 4 bytes */
    }


} __rte_cache_aligned;

static_assert(sizeof(CGenNodeStateless) == sizeof(CGenNode), "sizeof(CGenNodeStateless) != sizeof(CGenNode)" );


/* this is a event for PCAP transmitting */
struct CGenNodePCAP : public CGenNodeBase  {
friend class TrexStatelessDpPerPort;

public:

    /**
     * creates a node from a PCAP file 
     */
    bool create(uint8_t port_id,
                pkt_dir_t dir,
                socket_id_t socket_id,
                const uint8_t *mac_addr,
                const uint8_t *slave_mac_addr,
                const std::string &pcap_filename,
                double ipg_usec,
                double min_ipg_sec,
                double speedup,
                uint32_t count,
                bool is_dual);

    /**
     * destroy the node cleaning up any data
     * 
     */
    void destroy();
 
    bool is_dual() const {
        return m_is_dual;
    }

    /**
     * advance - will read the next packet
     * 
     * @author imarom (03-May-16)
     */
    void next() {
        assert(is_active());

        /* save the previous packet time */
        m_last_pkt_time = m_raw_packet->get_time();

        /* advance */
        if ( m_reader->ReadPacket(m_raw_packet) == false ){
            m_count--;

            /* if its the end - go home... */
            if (m_count == 0) {
                m_state = PCAP_INACTIVE;
                return;
            } 

            /* rewind and load the first packet */
            m_reader->Rewind();
            if (!m_reader->ReadPacket(m_raw_packet)) {
                m_state = PCAP_INACTIVE;
                return;
            }
        }

        /* update the packet dir if needed */
        update_pkt_dir();
      
    }


    inline void update_pkt_dir() {
        /* if dual mode and the interface is odd - swap the dir */
        if (is_dual()) {
            pkt_dir_t dir = (m_raw_packet->getInterface() & 0x1) ? (m_dir ^ 0x1) : m_dir;
            set_mbuf_dir(dir);
        }
    }

    /**
     * return the time for the next scheduling for a packet
     * 
     */
    inline double get_ipg() {
        assert(m_state != PCAP_INVALID);

        /* fixed IPG */
        if (m_ipg_sec != -1) {
            return m_ipg_sec;
        } else {
            return (std::max(m_min_ipg_sec, (m_raw_packet->get_time() - m_last_pkt_time) / m_speedup));
        }
    }

    /**
     * get the current packet as MBUF
     * 
     */
    inline rte_mbuf_t *get_pkt() {
        assert(m_state != PCAP_INVALID);

        rte_mbuf_t *m = CGlobalInfo::pktmbuf_alloc_local( get_socket_id(), m_raw_packet->getTotalLen());
        assert(m);

        char *p = rte_pktmbuf_append(m, m_raw_packet->getTotalLen());
        assert(p);

        /* copy the packet */
        memcpy(p, m_raw_packet->raw, m_raw_packet->getTotalLen());

        char *mac;
        if (get_mbuf_dir() == m_dir) {
            mac = (char*)m_mac_addr;
        } else {
            mac = (char*)m_slave_mac_addr;
        }

        if ( m_ex_flags & CGenNodePCAP::efANY_MAC ){
            uint8_t f = m_ex_flags & CGenNodePCAP::efANY_MAC;

            if (f == CGenNodePCAP::efDST_MAC){
                /* replace only src */
                memcpy(p+6, mac+6, 6);

            }else{
                if (f == CGenNodePCAP::efSRC_MAC){
                    /* replace only dest */
                    memcpy(p, mac, 6);
                }
            }
        }else{ 
            memcpy(p, mac, 12);
        }
        

        return (m);
    }


    inline void handle(CFlowGenListPerThread *thread) {
        assert(m_state != PCAP_INVALID);
        thread->m_node_gen.m_v_if->send_node( (CGenNode *)this);

        // read the next packet
        next();

        if (is_active()) {
            m_time += get_ipg();
            thread->m_node_gen.m_p_queue.push((CGenNode *)this);  
                            
        } else {
            TrexStatelessDpCore *stl_dp_core = (TrexStatelessDpCore *)thread->get_dp_core();
            int event_id = stl_dp_core->get_port_db(get_port_id())->get_event_id();
            stl_dp_core->stop_traffic(get_port_id(), 0, false, event_id);
        }
    }

    void set_mbuf_dir(pkt_dir_t dir) {
        if (dir) {
            m_flags |=NODE_FLAGS_DIR;
        }else{
            m_flags &=~NODE_FLAGS_DIR;
        }
    }

    inline pkt_dir_t get_mbuf_dir(){
        return ((pkt_dir_t)( m_flags &1));
    }

    void mark_for_free() {
        m_state = PCAP_MARKED_FOR_FREE;
    }

    bool is_active() {
        return (m_state == PCAP_ACTIVE);
    }

    bool is_marked_for_free() {
        return (m_state == PCAP_MARKED_FOR_FREE);
    }

private:

    enum {
        PCAP_INVALID = 0,
        PCAP_ACTIVE,
        PCAP_INACTIVE,
        PCAP_MARKED_FOR_FREE
    };

    /* flags */
    enum {
        efDST_MAC = 0x1,
        efSRC_MAC  = 0x2,
        efANY_MAC  = 0x3
    };

    /* cache line 0 */
    /* important stuff here */
    uint8_t             m_mac_addr[12];
    uint8_t             m_slave_mac_addr[12];
    uint8_t             m_state;

    pkt_dir_t           m_dir;

    double              m_last_pkt_time;
    double              m_speedup;
    double              m_ipg_sec;
    double              m_min_ipg_sec;
    uint32_t            m_count;

    double              m_next_time_offset; /* in sec */

    CCapReaderBase      *m_reader;
    CCapPktRaw          *m_raw_packet;
    
    uint8_t             m_pad5;

    bool                m_is_dual;
    
    uint8_t             m_ex_flags;

    /* pad to match the size of CGenNode */
    uint8_t             m_pad_end[10];

    /* CACHE_LINE */
    uint64_t            m_pad3[8];

} __rte_cache_aligned;


static_assert(sizeof(CGenNodePCAP) == sizeof(CGenNode), "sizeof(CGenNodePCAP) != sizeof(CGenNode)" );

/* this is a event for time synchronization. */
struct CGenNodeTimesync : public CGenNodeBase {
    friend class TrexStatelessDpCore;

  public:
    /* cache line 0 */
    /* important stuff here */
    dsec_t timesync_last;

  private:
    uint8_t m_mac_addr[12];
    uint16_t m_stat_hw_id; // hw id used to count rx and tx stats
    uint16_t m_cache_array_cnt;

    uint8_t m_null_stream;

    CGenNodeStateless::stream_state_t m_state;
    uint8_t m_stream_type; // see TrexStream::STREAM_TYPE, stream_type_t
    pkt_dir_t m_pkt_dir;
    uint32_t m_ip_addr;
    uint64_t m_pad_0[2];

    /* cache line 1 */
    /* this cache line would better be readonly but is not */
    TrexStream *m_ref_stream_info;
    rte_mbuf_t *m;
    CTimesyncEngine *m_timesync_engine;
    bool hardware_timestamping_enabled;
    uint8_t m_pad_1[7];
    uint64_t m_pad_2[2];

    uint8_t m_pad5;
    uint32_t m_profile_id;

    PTP::Field::message_type m_last_sent_ptp_packet_type;
    uint16_t m_last_sent_sequence_id;
    PTP::Field::src_port_id_field m_last_sent_ptp_src_port;
  public:
    dsec_t m_next_time_offset;

  private:
    uint64_t m_pad_3[6];

  public:

    inline void init() {
        m_timesync_engine = CGlobalInfo::get_timesync_engine();
        assert(m_timesync_engine);

        TrexPlatformApi &api = get_platform_api();
        hardware_timestamping_enabled = api.getPortAttrObj(m_port_id)->is_hardware_timesync_enabled();

        // Get Ip Addr
        m_ip_addr = CGlobalInfo::m_options.m_ip_cfg[m_port_id].get_ip();

        set_slow_path(true);
        set_send_immediately(true);

    }

    inline void teardown() {
        m_timesync_engine = nullptr;
    }

    inline void handle(CFlowGenListPerThread *thread) {
        if (timesync_last + static_cast<double>(CGlobalInfo::m_options.m_timesync_interval) < now_sec()) {
            if (hardware_timestamping_enabled) {
                /*Read values from NIC to prevent latching with old value. */
                timespec ts_temp;
                int i = 0;
                while (i == 0) {
                    i = rte_eth_timesync_read_tx_timestamp(m_port_id, &ts_temp);
                }
            }

            m_timesync_engine->pushNextMessage(m_port_id, m_timesync_engine->nextSequenceId(),
                                               PTP::Field::message_type::SYNC, {0, 0});
            timesync_last = now_sec();  // store timestamp of the last (this) time synchronization
        }

        if (m_timesync_engine->hasNextMessage(m_port_id)) {
            timespec ts;
            thread->m_node_gen.m_v_if->send_node((CGenNode *)this);
            int i;
            if (hardware_timestamping_enabled) {
                /* Wait at least 1 us to read TX timestamp. */
                int wait_us = 0;

                i = rte_eth_timesync_read_tx_timestamp(m_port_id, &ts);
                while ((i < 0) && (wait_us < 1000)) {
                    rte_delay_us(1);
                    wait_us++;
                    i = rte_eth_timesync_read_tx_timestamp(m_port_id, &ts);
                }
            } else if (CGlobalInfo::m_options.is_timesync_tx_callback_enabled()) {
                i = m_timesync_engine->getTxTimestamp(m_port_id, m_last_sent_sequence_id, &ts);
            } else {
                i = clock_gettime(CLOCK_REALTIME, &ts);
            }
            if (i != 0) {
                printf("Error in PTP synchronization - failed to read tx timestamp, error code: %i\n", i);
                return;
            }

            switch (m_last_sent_ptp_packet_type)
            {
            case PTP::Field::message_type::SYNC:
                m_timesync_engine->sentPTPSync(m_port_id, m_last_sent_sequence_id, ts);
                break;
            case PTP::Field::message_type::PDELAY_REQ:
                m_timesync_engine->sentPTPDelayReq(m_port_id, m_last_sent_sequence_id, ts, m_last_sent_ptp_src_port);
                break;
            case PTP::Field::message_type::FOLLOW_UP:
                if (hardware_timestamping_enabled) {
                    /*Read values from NIC to prevent latching with old value. */
                    int i = 0;
                    timespec ts_temp;
                    while (i == 0) {
                        i = rte_eth_timesync_read_rx_timestamp(m_port_id, &ts_temp, 0);
                    }
                }
                break;

            default:
                break;
            }
        }
    }

    template<typename PTPMsgType>
    PTPMsgType* prepare_packet(rte_mbuf_t* mbuf, const CTimesyncPTPPacketData_t& next_msg) {
        size_t size = 0;

        EthernetHeader* eth_hdr = rte_pktmbuf_mtod(mbuf, EthernetHeader*);
        size += ETH_HDR_LEN;
        eth_hdr->mySource = { m_mac_addr[6], m_mac_addr[7], m_mac_addr[8], m_mac_addr[9], m_mac_addr[10], m_mac_addr[11] };

        IPHeader* ipv4_hdr = nullptr;
        UDPHeader* udp_hdr = nullptr;

        if (CGlobalInfo::m_options.is_timesync_L2()) {
            eth_hdr->setNextProtocol(EthernetHeader::Protocol::PTP);

        } else { // If UDP
            eth_hdr->setNextProtocol(EthernetHeader::Protocol::IP);

            ipv4_hdr = rte_pktmbuf_mtod_offset(mbuf, IPHeader*, size);
            size += IPV4_HDR_LEN;

            ipv4_hdr->setVersion(4);
            ipv4_hdr->setHeaderLength(IPV4_HDR_LEN);
            ipv4_hdr->setProtocol(IPHeader::Protocol::UDP);
            ipv4_hdr->setTimeToLive(1);
            ipv4_hdr->setSourceIp(m_ip_addr);
            ipv4_hdr->setFragment(0, false, true);
            
            // IP Addr = 224.0.1.129 (multicast ip addr for PTP)
            // Source: https://www.iana.org/assignments/multicast-addresses/multicast-addresses.xhtml
            ipv4_hdr->setDestIp(0xE0000181);

            // Set IPv4mcast for PTP multicast ip
            // Source: https://techhub.hpe.com/eginfolib/networking/docs/switches/5130ei/5200-3944_ip-multi_cg/content/483573739.htm
            eth_hdr->myDestination = { 0x01, 0x00, 0x5e, 0x00, 0x01, 0x81 };

            udp_hdr = rte_pktmbuf_mtod_offset(mbuf, UDPHeader*, size);
            size += UDP_HEADER_LEN;
        }

        // Setup PTP message
        PTP::Header* ptp_hdr = rte_pktmbuf_mtod_offset(mbuf, PTP::Header*, size);

        ptp_hdr->trn_and_msg = PTP::Field::transport_specific::DEFAULT;

        ptp_hdr->ver = PTP::Field::version::PTPv2;

        // "The PTP frames are sent on UDP ports 319 (ptp-event) and 320 (ptp-general)."
        // Source: http://wiki.hevs.ch/uit/index.php5/Standards/Ethernet_PTP
        switch(PTPMsgType::type){
            case PTP::Field::message_type::SYNC:
                ptp_hdr->trn_and_msg = PTP::Field::message_type::SYNC;
                ptp_hdr->message_len = PTP_SYNC_LEN;
                ptp_hdr->flag_field = PTP::Field::flags::PTP_TWO_STEP | PTP::Field::flags::PTP_UNICAST;
                ptp_hdr->control = PTP::Field::control::CTL_SYNC;
                if (udp_hdr) {
                    udp_hdr->setSourcePort(319);
                    udp_hdr->setDestPort(319);
                }
                break;

            case PTP::Field::message_type::FOLLOW_UP:
                ptp_hdr->trn_and_msg = PTP::Field::message_type::FOLLOW_UP;
                ptp_hdr->message_len = PTP_FOLLOWUP_LEN;
                ptp_hdr->flag_field = PTP::Field::flags::PTP_NONE;
                ptp_hdr->control = PTP::Field::control::CTL_FOLLOW_UP;
                if (udp_hdr) {
                    udp_hdr->setSourcePort(320);
                    udp_hdr->setDestPort(320);
                }
                break;

            case PTP::Field::message_type::PDELAY_REQ:
                ptp_hdr->trn_and_msg = PTP::Field::message_type::PDELAY_REQ;
                ptp_hdr->message_len = PTP_DELAYREQ_LEN;
                ptp_hdr->flag_field = PTP::Field::flags::PTP_NONE;
                ptp_hdr->control = PTP::Field::control::CTL_DELAY_REQ;
                if (udp_hdr) {
                    udp_hdr->setSourcePort(319);
                    udp_hdr->setDestPort(319);
                }
                m_last_sent_ptp_src_port = ptp_hdr->source_port_id;
                break;

            case PTP::Field::message_type::DELAY_RESP:
                ptp_hdr->trn_and_msg = PTP::Field::message_type::DELAY_RESP;
                ptp_hdr->message_len = PTP_DELAYRESP_LEN;
                ptp_hdr->flag_field = PTP::Field::flags::PTP_NONE;
                ptp_hdr->control = PTP::Field::control::CTL_DELAY_RESP;
                if (udp_hdr) {
                    udp_hdr->setSourcePort(320);
                    udp_hdr->setDestPort(320);
                }
                break;
            default:
                assert(0);
                break;
        }

        ptp_hdr->domain_number = 0;
        //ptp_hdr->reserved1;
        ptp_hdr->correction = 0;
        //ptp_hdr->reserved2;

        ptp_hdr->source_port_id._clock_id.b[0] = eth_hdr->mySource.data[0];
        ptp_hdr->source_port_id._clock_id.b[1] = eth_hdr->mySource.data[1];
        ptp_hdr->source_port_id._clock_id.b[2] = eth_hdr->mySource.data[2];
        ptp_hdr->source_port_id._clock_id.b[3] = 0xFF;
        ptp_hdr->source_port_id._clock_id.b[4] = 0xFE;
        ptp_hdr->source_port_id._clock_id.b[5] = eth_hdr->mySource.data[3];
        ptp_hdr->source_port_id._clock_id.b[6] = eth_hdr->mySource.data[4];
        ptp_hdr->source_port_id._clock_id.b[7] = eth_hdr->mySource.data[5];

        ptp_hdr->source_port_id._port_number = m_port_id;

        ptp_hdr->seq_id = next_msg.sequence_id;
        ptp_hdr->log_message_interval = 127;

        size += PTP_HDR_LEN;

        // Setup PTP sync
        PTPMsgType* ptp_msg = rte_pktmbuf_mtod_offset(mbuf, PTPMsgType*, size);

        ptp_msg->origin_timestamp.sec_msb = 0;
        ptp_msg->origin_timestamp.sec_lsb = next_msg.time_to_send.tv_sec;
        ptp_msg->origin_timestamp.ns = next_msg.time_to_send.tv_nsec;
        size += PTPMsgType::size;

        // Set mbuf data
        // Enable flag for hardware timestamping.
        mbuf->ol_flags |= PKT_TX_IEEE1588_TMST;

        // Set pkt size
        m->data_len = size;
        m->pkt_len = size;

        // Update length for IP and UDP headers
        if (ipv4_hdr != nullptr && udp_hdr != nullptr) {
            ipv4_hdr->setTotalLength(size - ETH_HDR_LEN);
            udp_hdr->setLength(size - ETH_HDR_LEN - IPV4_HDR_LEN);
            ipv4_hdr->updateCheckSum();
            udp_hdr->updateCheckSum(ipv4_hdr);
        }

        return ptp_msg;

    }

    /**
     * get the current packet as MBUF
     */
    inline rte_mbuf_t *get_pkt() {
        // NextMessage next_message = m_timesync_engine->getNextMessage(m_port_id);
        CTimesyncPTPPacketData_t next_message = m_timesync_engine->popNextMessage(m_port_id);
        m_last_sent_ptp_packet_type = next_message.type;
        m_last_sent_sequence_id = next_message.sequence_id;
        m_last_sent_ptp_src_port = next_message.source_port_id;

        switch (next_message.type) {

        case PTP::Field::message_type::SYNC: {
            prepare_packet<PTP::SyncPacket>(m, next_message);
        } break;

        case PTP::Field::message_type::FOLLOW_UP: {
            prepare_packet<PTP::FollowUpPacket>(m, next_message);
        } break;

        case PTP::Field::message_type::PDELAY_REQ: {
            prepare_packet<PTP::DelayedReqPacket>(m, next_message);
        } break;

        case PTP::Field::message_type::DELAY_RESP: {
            PTP::DelayedRespPacket* ptp_delresp = prepare_packet<PTP::DelayedRespPacket>(m, next_message);
            ptp_delresp->req_clock_identity = next_message.source_port_id;
        } break;

        default:
            break;
        }

        return (m);
    }

    inline CGenNodeStateless::stream_state_t get_state() { return m_state; }

    inline bool is_mask_for_free() { return (m_state == CGenNodeStateless::ss_FREE_RESUSE ? true : false); }

    inline void mark_for_free() { m_state = CGenNodeStateless::ss_FREE_RESUSE; }

    inline uint8_t get_stream_type() { return (m_stream_type); }

    // for linux case
    inline void allocate_m(rte_mempool_t * mp1) {
        m = rte_pktmbuf_alloc(mp1);
    }

} __rte_cache_aligned;

static_assert(sizeof(CGenNodeTimesync) == sizeof(CGenNode), "sizeof(CGenNodeTimesync) != sizeof(CGenNode)");

#endif /* __TREX_STL_STREAM_NODE_H__ */
