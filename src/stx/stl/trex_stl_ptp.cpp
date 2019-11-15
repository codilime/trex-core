// #include <common/Network/Packet/EthernetHeader.h>

#include <rte_ether.h>
#include <rte_ethdev.h>

#include "trex_stl_ptp.h"

static const struct ether_addr ether_multicast = {
	//.addr_bytes = {0x01, 0x1b, 0x19, 0x0, 0x0, 0x0}
    .addr_bytes = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
};

using namespace PTP;

size_t PTPEngine::pkt_size(){
    return sizeof(struct ether_hdr) + sizeof(struct ptp_message);
}

// template<typename T,int size>
// void set_table(T& tbl_a[size], T& tbl_b[size]){
//     for(int i = 0; i < size; i++)
//         tbl_a[i] = tbl_b[i];
// }

// void set_clock_id(struct clock_id& clock, uint8_t new_clock[8]){
//     set_table(clock.id, new_clock);
// }

void PTPEngine::set_port_id(PTP::port_id* port_id, ether_hdr* eth_hdr) {
    // 3 bytes  from MAC Addr
    // 0xFF 0xFE
    // next 3 bytes from MAC Addr
    port_id->clock_id.id[0] = eth_hdr->s_addr.addr_bytes[0];
    port_id->clock_id.id[1] = eth_hdr->s_addr.addr_bytes[1];
    port_id->clock_id.id[2] = eth_hdr->s_addr.addr_bytes[2];
    port_id->clock_id.id[3] = 0xFF;
    port_id->clock_id.id[4] = 0xFE;
    port_id->clock_id.id[5] = eth_hdr->s_addr.addr_bytes[3];
    port_id->clock_id.id[6] = eth_hdr->s_addr.addr_bytes[4];
    port_id->clock_id.id[7] = eth_hdr->s_addr.addr_bytes[5];

    port_id->port_number = 0;
}

void PTPEngine::prepare_header(ptp_header* header, PTP::message_type type, uint16_t seq_number) {
    assert(header);

    header->msg_type = type;
    header->ver = PTP::version::PTPv2;
    header->message_length = htons(sizeof(ptp_message));
    header->domain_number = 0;
    // header->reserved1 = 0;
    header->correction = 0;
    // header->reserved2 = 0;

    header->seq_id = htons(seq_number);

    header->flag_field = PTP::PTP_NONE;

    header->control = PTP::controlField::CTL_SYNC;
    header->log_message_interval = 127;
}

/* Prepare message */
bool PTPEngine::prepare_sync(rte_mbuf_t* mbuf) {
    assert(mbuf);

    // Setup mbuf common
    mbuf->data_len = pkt_size();
    mbuf->pkt_len = pkt_size();

    // Setup Ethernet header
    ether_hdr* eth_hdr = rte_pktmbuf_mtod(mbuf, ether_hdr *);
    rte_eth_macaddr_get(0, &eth_hdr->s_addr);
    eth_hdr->ether_type = htons(PTP_PROTOCOL);

    /* Set multicast address 01-1B-19-00-00-00. */
    ether_addr_copy(&ether_multicast, &eth_hdr->d_addr);

    // Setup PTP message
    ptp_message* ptp_msg = rte_pktmbuf_mtod_offset(mbuf, ptp_message*, sizeof(ether_hdr));

    // Setup PTP header
    ptp_header* ptp_hdr = &(ptp_msg->sync.hdr);

    prepare_header(ptp_hdr, PTP::message_type::SYNC, 0);
    ptp_hdr->flag_field = PTP::flag_field::PTP_TWO_STEP;
    set_port_id(&(ptp_hdr->source_port_id), eth_hdr);

    // Enable flag for hardware timestamping.
    mbuf->ol_flags |= PKT_TX_IEEE1588_TMST;

    // Setup PTP sync
    // As we do not support PTP_ONE_WAY currently, this is set to 0
    ptp_msg->sync.origin_tstamp.sec_msb = 0;
    ptp_msg->sync.origin_tstamp.sec_lsb = 0;
    ptp_msg->sync.origin_tstamp.ns = 0;

    return true;
}

bool PTPEngine::prepare_follow_up(rte_mbuf_t* mbuf, struct tstamp* t) {
    assert(mbuf);

    // Setup mbuf common
    mbuf->data_len = pkt_size();
    mbuf->pkt_len = pkt_size();

    // Setup Ethernet header
    ether_hdr* eth_hdr = rte_pktmbuf_mtod(mbuf, ether_hdr *);
    rte_eth_macaddr_get(0, &eth_hdr->s_addr);
    eth_hdr->ether_type = htons(PTP_PROTOCOL);

    /* Set multicast address 01-1B-19-00-00-00. */
    ether_addr_copy(&ether_multicast, &eth_hdr->d_addr);

    // Setup PTP message
    ptp_message* ptp_msg = rte_pktmbuf_mtod_offset(mbuf, ptp_message*, sizeof(ether_hdr));

    // Setup PTP header
    ptp_header* ptp_hdr = &(ptp_msg->follow_up.hdr);

    prepare_header(ptp_hdr, PTP::message_type::FOLLOW_UP, 0);
    set_port_id(&(ptp_hdr->source_port_id), eth_hdr);

    /* Enable flag for hardware timestamping. */
    mbuf->ol_flags |= PKT_TX_IEEE1588_TMST;

    // Setup PTP sync
    ptp_msg->follow_up.precise_origin_tstamp.sec_msb = htons(t->sec_msb);
    ptp_msg->follow_up.precise_origin_tstamp.sec_lsb = htonl(t->sec_lsb);
    ptp_msg->follow_up.precise_origin_tstamp.ns = htonl(t->ns);

    return true;
}

bool PTPEngine::prepare_delayed_req(rte_mbuf_t* mbuf) {
    assert(mbuf);

    // Setup mbuf common
    mbuf->data_len = pkt_size();
    mbuf->pkt_len = pkt_size();

    // Setup Ethernet header
    ether_hdr* eth_hdr = rte_pktmbuf_mtod(mbuf, ether_hdr *);
    rte_eth_macaddr_get(0, &eth_hdr->s_addr);
    eth_hdr->ether_type = htons(PTP_PROTOCOL);

    /* Set multicast address 01-1B-19-00-00-00. */
    ether_addr_copy(&ether_multicast, &eth_hdr->d_addr);

    // Setup PTP message
    ptp_message* ptp_msg = rte_pktmbuf_mtod_offset(mbuf, ptp_message*, sizeof(ether_hdr));

    // Setup PTP header
    ptp_header* ptp_hdr = &(ptp_msg->delay_req.hdr);

    prepare_header(ptp_hdr, PTP::message_type::DELAY_REQ, 0);
    set_port_id(&(ptp_hdr->source_port_id), eth_hdr);

    /* Enable flag for hardware timestamping. */
    mbuf->ol_flags |= PKT_TX_IEEE1588_TMST;

    // Setup PTP delayed request
    // As we do not support PTP_ONE_WAY currently, this is set to 0
    ptp_msg->delay_req.origin_tstamp.sec_msb = 0;
    ptp_msg->delay_req.origin_tstamp.sec_lsb = 0;
    ptp_msg->delay_req.origin_tstamp.ns = 0;

    return true;
}

bool PTPEngine::prepare_delayed_resp(rte_mbuf_t* mbuf, struct tstamp* t) {
    assert(mbuf);

    // Setup mbuf common
    mbuf->data_len = pkt_size();
    mbuf->pkt_len = pkt_size();

    // Setup Ethernet header
    ether_hdr* eth_hdr = rte_pktmbuf_mtod(mbuf, ether_hdr *);
    rte_eth_macaddr_get(0, &eth_hdr->s_addr);
    eth_hdr->ether_type = htons(PTP_PROTOCOL);

    /* Set multicast address 01-1B-19-00-00-00. */
    ether_addr_copy(&ether_multicast, &eth_hdr->d_addr);

    // Setup PTP message
    ptp_message* ptp_msg = rte_pktmbuf_mtod_offset(mbuf, ptp_message*, sizeof(ether_hdr));

    // Setup PTP header
    ptp_header* ptp_hdr = &(ptp_msg->delay_resp.hdr);

    prepare_header(ptp_hdr, PTP::message_type::DELAY_RESP, 0);
    set_port_id(&(ptp_hdr->source_port_id), eth_hdr);

    /* Enable flag for hardware timestamping. */
    mbuf->ol_flags |= PKT_TX_IEEE1588_TMST;

    // Setup PTP delayed response
    set_port_id(&(ptp_msg->delay_resp.req_port_id), eth_hdr);

    ptp_msg->delay_resp.rx_tstamp.sec_msb = htons(t->sec_msb);
    ptp_msg->delay_resp.rx_tstamp.sec_lsb = htonl(t->sec_lsb);
    ptp_msg->delay_resp.rx_tstamp.ns = htonl(t->ns);

    return true;
}

/* Parse message */
bool PTPEngine::parse_sync(rte_mbuf_t* mbuf) {
    return true;
}

bool PTPEngine::parse_follow_up(rte_mbuf_t* mbuf, struct tstamp* t) {
    return true;
}

bool PTPEngine::parse_delayed_req(rte_mbuf_t* mbuf) {
    return true;
}

bool parse_delayed_resp(rte_mbuf_t* mbuf) {
    return true;
}

/* Helper methods */
int64_t PTPEngine::delta_eval(const struct timespec& time1, const struct timespec& time2,
                              const struct timespec& time3, const struct timespec& time4) {
    int64_t delta;
    uint64_t t1 = 0;
    uint64_t t2 = 0;
    uint64_t t3 = 0;
    uint64_t t4 = 0;

    t1 = timespec64_to_ns(time1);
    t2 = timespec64_to_ns(time2);
    t3 = timespec64_to_ns(time3);
    t4 = timespec64_to_ns(time4);

    delta = -((int64_t)((t2 - t1) - (t4 - t3))) / 2;

    return delta;
}

uint64_t PTPEngine::timespec64_to_ns(const struct timespec& ts){
    return ((uint64_t) ts.tv_sec * NSEC_PER_SEC) + ts.tv_nsec;
}

struct timeval PTPEngine::ns_to_timeval(int64_t nsec){
    struct timespec t_spec = {0, 0};
    struct timeval t_eval = {0, 0};
    int32_t rem;

    if (nsec == 0)
        return t_eval;
    rem = nsec % NSEC_PER_SEC;
    t_spec.tv_sec = nsec / NSEC_PER_SEC;

    if (rem < 0) {
        t_spec.tv_sec--;
        rem += NSEC_PER_SEC;
    }

    t_spec.tv_nsec = rem;
    t_eval.tv_sec = t_spec.tv_sec;
    t_eval.tv_usec = t_spec.tv_nsec / 1000;

    return t_eval;
}