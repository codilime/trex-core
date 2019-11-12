#ifndef __TREX_STL_PTP_H__
#define __TREX_STL_PTP_H__

#include <cstdint>
#include <rte_ethdev.h>

#define NSEC_PER_SEC        1000000000L
#define KERNEL_TIME_ADJUST_LIMIT  20000
#define PTP_PROTOCOL             0x88F7

// struct ptpv2_data_slave_ordinary {
//     struct rte_mbuf *m;
//     struct timespec tstamp1;
//     struct timespec tstamp2;
//     struct timespec tstamp3;
//     struct timespec tstamp4;
//     struct clock_id client_clock_id;
//     struct clock_id master_clock_id;
//     struct timeval new_adj;
//     int64_t delta;
//     uint16_t portid;
//     uint16_t seqID_SYNC;
//     uint16_t seqID_FOLLOWUP;
//     uint8_t ptpset;
//     uint8_t kernel_time_set;
//     uint16_t current_ptp_port;
// };

//static struct ptpv2_data_slave_ordinary ptp_data;

/* Values for the PTP messageType field. */
namespace PTP {

enum struct message_type : uint8_t {
    SYNC = 0x0,
    DELAY_REQ = 0x1,
    PDELAY_REQ = 0x2,
    PDELAY_RESP = 0x3,
    FOLLOW_UP = 0x8,
    DELAY_RESP = 0x9,
    PDELAY_RESP_FOLLOW_UP = 0xA,
    ANNOUNCE = 0xB,
    SIGNALING = 0xC,
    MANAGEMENT = 0xD
};

enum struct version : uint8_t {
    PTPv1 = 0x1,
    PTPv2 = 0x2
};

typedef uint16_t message_lenght;
typedef uint8_t domain_number;
struct flag_field {
    uint8_t hb;
    uint8_t lb;
} __attribute__((packed));

struct tstamp {
    uint16_t   sec_msb;
    uint32_t   sec_lsb;
    uint32_t   ns;
}  __attribute__((packed));

struct clock_id {
    uint8_t id[8];
};

struct port_id {
    struct clock_id        clock_id;
    uint16_t               port_number;
}  __attribute__((packed));

struct ptp_header {
    PTP::message_type    msg_type;
    PTP::version         ver;
    PTP::message_lenght  message_length;
    PTP::domain_number   domain_number;
    uint8_t              reserved1;
    PTP::flag_field      flag_field;
    int64_t              correction;
    uint32_t             reserved2;
    struct port_id       source_port_id;
    uint16_t             seq_id;
    uint8_t              control;
    int8_t               log_message_interval;
} __attribute__((packed));

struct sync_msg {
    struct ptp_header   hdr;
    struct tstamp       origin_tstamp;
} __attribute__((packed));

struct follow_up_msg {
    struct ptp_header   hdr;
    struct tstamp       precise_origin_tstamp;
    uint8_t             suffix[0];
} __attribute__((packed));

struct delay_req_msg {
    struct ptp_header   hdr;
    struct tstamp       origin_tstamp;
} __attribute__((packed));

struct delay_resp_msg {
    struct ptp_header    hdr;
    struct tstamp        rx_tstamp;
    struct port_id       req_port_id;
    uint8_t              suffix[0];
} __attribute__((packed));

struct ptp_message {
    union {
        struct ptp_header          header;
        struct sync_msg            sync;
        struct delay_req_msg       delay_req;
        struct follow_up_msg       follow_up;
        struct delay_resp_msg      delay_resp;
    } __attribute__((packed));
};

class PTPEngine {

public:

    static size_t pkt_size(){
        return sizeof(struct ether_hdr) + sizeof(struct ptp_message);
    }

    static void set_clock_id(struct clock_id& clock, uint8_t new_clock[8]){
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
    // static void set_table(T& tbl_a[size], T& tbl_b[size]){
    //     for(int i = 0; i < size; i++)
    //         tbl_a[i] = tbl_b[i];
    // }

    // static void set_clock_id(struct clock_id& clock, uint8_t new_clock[8]){
    //     set_table(clock.id, new_clock);
    // }

    static void prepare_header(ptp_header* header){
        assert(header);

        header->msg_type = PTP::message_type::SYNC;
        header->ver = PTP::version::PTPv2;
        header->message_length = sizeof(struct ptp_message);
        header->domain_number = 0;
        // header->reserved1 = 0;
        header->flag_field.hb = 0;
        header->flag_field.lb = 0;
        header->correction = 0;

        //header->source_port_id.clock_id
        //header->source_port_id.port_number = 0;

        //header->seq_id = htons(ptp_data->seqID_SYNC);
        //header->msg_type = DELAY_REQ;
        
        //header->control = 1;
        //header->log_message_interval = 127;
    }

    /* Prepare message */
    static bool prepare_sync(rte_mbuf_t* mbuf){
        assert(mbuf);

        mbuf->data_len = pkt_size();
        mbuf->pkt_len = pkt_size();

        struct ether_hdr* eth_hdr = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
        //rte_eth_macaddr_get(ptp_data->portid, &eth_hdr->s_addr);

        /* Set multicast address 01-1B-19-00-00-00. */
        //ether_addr_copy(&eth_multicast, &eth_hdr->d_addr);

        eth_hdr->ether_type = htons(PTP_PROTOCOL);
        struct ptp_message* ptp_msg = (struct ptp_message *)
            (rte_pktmbuf_mtod(mbuf, char *) + sizeof(struct ether_hdr));

        ptp_msg->header.ver = PTP::version::PTPv2;
        // ptp_msg->delay_req.hdr.msg_type = DELAY_REQ;
        // ptp_msg->delay_req.hdr.ver = 2;
        // ptp_msg->delay_req.hdr.control = 1;
        // ptp_msg->delay_req.hdr.log_message_interval = 127;

        // /* Set up clock id. */
        // client_clkid =
        // 	&ptp_msg->delay_req.hdr.source_port_id.clock_id;

        // client_clkid->id[0] = eth_hdr->s_addr.addr_bytes[0];
        // client_clkid->id[1] = eth_hdr->s_addr.addr_bytes[1];
        // client_clkid->id[2] = eth_hdr->s_addr.addr_bytes[2];
        // client_clkid->id[3] = 0xFF;
        // client_clkid->id[4] = 0xFE;
        // client_clkid->id[5] = eth_hdr->s_addr.addr_bytes[3];
        // client_clkid->id[6] = eth_hdr->s_addr.addr_bytes[4];
        // client_clkid->id[7] = eth_hdr->s_addr.addr_bytes[5];

        // rte_memcpy(&ptp_data->client_clock_id,
        // 	   client_clkid,
        // 	   sizeof(struct clock_id));

        // /* Enable flag for hardware timestamping. */
        // created_pkt->ol_flags |= PKT_TX_IEEE1588_TMST;

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

    static bool prepare_follow_up(rte_mbuf_t* mbuf, struct tstamp* t) {
        return true;
    }

    static bool prepare_delayed_req(rte_mbuf_t* mbuf) {
        return true;
    }

    static bool prepare_delayed_resp(rte_mbuf_t* mbuf) {
        return true;
    }

    /* Parse message */
    static bool parse_sync(rte_mbuf_t* mbuf) {
        return true;
    }

    static bool parse_follow_up(rte_mbuf_t* mbuf, struct tstamp* t) {
        return true;
    }

    static bool parse_delayed_req(rte_mbuf_t* mbuf) {
        return true;
    }

    static bool parse_delayed_resp(rte_mbuf_t* mbuf) {
        return true;
    }

    /* Helper methods */
    /*static int64_t delta_eval(struct ptpv2_data_slave_ordinary *ptp_data){
        int64_t delta;
        uint64_t t1 = 0;
        uint64_t t2 = 0;
        uint64_t t3 = 0;
        uint64_t t4 = 0;

        t1 = timespec64_to_ns(&ptp_data->tstamp1);
        t2 = timespec64_to_ns(&ptp_data->tstamp2);
        t3 = timespec64_to_ns(&ptp_data->tstamp3);
        t4 = timespec64_to_ns(&ptp_data->tstamp4);

        delta = -((int64_t)((t2 - t1) - (t4 - t3))) / 2;

        return delta;
    }*/

private:
    static uint64_t timespec64_to_ns(const struct timespec *ts){
        return ((uint64_t) ts->tv_sec * NSEC_PER_SEC) + ts->tv_nsec;
    }

    static struct timeval ns_to_timeval(int64_t nsec){
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
};

}

#endif /* __TREX_STL_PTP_H__ */