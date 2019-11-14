// #include <common/Network/Packet/EthernetHeader.h>

#include <rte_ether.h>
#include <rte_ethdev.h>

#include "trex_stl_ptp.h"

static const struct ether_addr ether_multicast = {
	.addr_bytes = {0x01, 0x1b, 0x19, 0x0, 0x0, 0x0}
};

using namespace PTP;

size_t PTPEngine::pkt_size(){
    return sizeof(struct ether_hdr) + sizeof(struct ptp_message);
}

void set_clock_id(struct clock_id& clock, uint8_t* new_clock) {
    clock.id[0] = new_clock[0];
    clock.id[1] = new_clock[1];
    clock.id[2] = new_clock[2];
    clock.id[3] = new_clock[3];
    clock.id[4] = new_clock[4];
    clock.id[5] = new_clock[5];
    clock.id[6] = new_clock[6];
    clock.id[7] = new_clock[7];
}

// template<typename T,int size>
// void set_table(T& tbl_a[size], T& tbl_b[size]){
//     for(int i = 0; i < size; i++)
//         tbl_a[i] = tbl_b[i];
// }

// void set_clock_id(struct clock_id& clock, uint8_t new_clock[8]){
//     set_table(clock.id, new_clock);
// }

void PTPEngine::prepare_header(ptp_header* header, PTP::message_type type, uint16_t seq_number) {
    assert(header);

    header->msg_type = type;
    header->ver = PTP::version::PTPv2;
    header->message_length = htons(sizeof(struct ptp_message));
    header->domain_number = 0;
    // header->reserved1 = 0;
    header->flag_field.hb = 0;
    header->flag_field.lb = 0;
    header->correction = 0;
    // header->reserved2 = 0;

    // set_clock_id(header->source_port_id.clock_id, &master_clock_id);
    header->source_port_id.clock_id.id[0] = 0;
    header->source_port_id.clock_id.id[1] = 0;
    header->source_port_id.clock_id.id[2] = 0;
    header->source_port_id.clock_id.id[3] = 0;
    header->source_port_id.clock_id.id[4] = 0;
    header->source_port_id.clock_id.id[5] = 0;
    header->source_port_id.clock_id.id[6] = 0;
    header->source_port_id.clock_id.id[7] = 1;

    header->source_port_id.port_number = 0;

    header->seq_id = htons(seq_number);

    header->control = 0;
    header->log_message_interval = 127;
}

/* Prepare message */
bool PTPEngine::prepare_sync(rte_mbuf_t* mbuf) {
    assert(mbuf);

    mbuf->data_len = pkt_size();
    mbuf->pkt_len = pkt_size();

    struct ether_hdr* eth_hdr = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
    rte_eth_macaddr_get(0, &eth_hdr->s_addr);
    eth_hdr->ether_type = htons(PTP_PROTOCOL);

    /* Set multicast address 01-1B-19-00-00-00. */
    ether_addr_copy(&ether_multicast, &eth_hdr->d_addr);

    //eth_hdr->ether_type = htons(PTP_PROTOCOL);
    struct ptp_message* ptp_msg = (struct ptp_message *)
        (rte_pktmbuf_mtod(mbuf, char *) + sizeof(struct ether_hdr));

    prepare_header(&(ptp_msg->header), PTP::message_type::SYNC, 0);

    /* Enable flag for hardware timestamping. */
    mbuf->ol_flags |= PKT_TX_IEEE1588_TMST;

    ptp_msg->sync.origin_tstamp.sec_msb = htons(0xDEAD);
    ptp_msg->sync.origin_tstamp.sec_lsb = htons(0xBEEF);
    ptp_msg->sync.origin_tstamp.ns = htons(0xCAFE);

    // /*Read value from NIC to prevent latching with old value. */
    // rte_eth_timesync_read_tx_timestamp(ptp_data->portid,
    // 		&ptp_data->tstamp3);

    // /* Transmit the packet. */
    // rte_eth_tx_burst(ptp_data->portid, 0, &created_pkt, 1);

    // wait_us = 0;
    // ptp_data->tstamp3.tv_nsec = 0;
    // ptp_data->tstamp3.tv_sec = 0;

    // /* Wait at least 1 us to read TX timestamp. */
    // while ((rte_eth_timesync_read_tx_timestamp(ptp_data->portid,
    // 		&ptp_data->tstamp3) < 0) && (wait_us < 1000)) {
    // 	rte_delay_us(1);
    // 	wait_us++;
    // }
    return true;
}

bool PTPEngine::prepare_follow_up(rte_mbuf_t* mbuf, struct tstamp* t) {
    return true;
}

bool PTPEngine::prepare_delayed_req(rte_mbuf_t* mbuf) {
    return true;
}

bool PTPEngine::prepare_delayed_resp(rte_mbuf_t* mbuf) {
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