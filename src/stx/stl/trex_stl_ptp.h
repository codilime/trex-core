#ifndef __TREX_STL_PTP_H__
#define __TREX_STL_PTP_H__

#include <cstdint>

/* Values for the PTP messageType field. */
#define SYNC                  0x0
#define DELAY_REQ             0x1
#define PDELAY_REQ            0x2
#define PDELAY_RESP           0x3
#define FOLLOW_UP             0x8
#define DELAY_RESP            0x9
#define PDELAY_RESP_FOLLOW_UP 0xA
#define ANNOUNCE              0xB
#define SIGNALING             0xC
#define MANAGEMENT            0xD

#define NSEC_PER_SEC        1000000000L
#define KERNEL_TIME_ADJUST_LIMIT  20000
#define PTP_PROTOCOL             0x88F7

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
	uint8_t              msg_type;
	uint8_t              ver;
	uint16_t             message_length;
	uint8_t              domain_number;
	uint8_t              reserved1;
	uint8_t              flag_field[2];
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

struct ptpv2_data_slave_ordinary {
	struct rte_mbuf *m;
	struct timespec tstamp1;
	struct timespec tstamp2;
	struct timespec tstamp3;
	struct timespec tstamp4;
	struct clock_id client_clock_id;
	struct clock_id master_clock_id;
	struct timeval new_adj;
	int64_t delta;
	uint16_t portid;
	uint16_t seqID_SYNC;
	uint16_t seqID_FOLLOWUP;
	uint8_t ptpset;
	uint8_t kernel_time_set;
	uint16_t current_ptp_port;
};

static struct ptpv2_data_slave_ordinary ptp_data;

class PTPEngine {

public:

    /* Prepare message */
    static bool prepare_sync(rte_mbuf_t* mbuf){}

    static bool prepare_follow_up(rte_mbuf_t* mbuf, struct tstamp* t){}

    static bool prepare_delayed_req(rte_mbuf_t* mbuf){}

    static bool prepare_delayed_resp(rte_mbuf_t* mbuf){}

    /* Parse message */
    static bool parse_sync(rte_mbuf_t* mbuf){}

    static bool parse_follow_up(rte_mbuf_t* mbuf, struct tstamp* t){}

    static bool parse_delayed_req(rte_mbuf_t* mbuf){}

    static bool parse_delayed_resp(rte_mbuf_t* mbuf){}

    /* Helper methods */
    static int64_t delta_eval(struct ptpv2_data_slave_ordinary *ptp_data){
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
    }

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
}

#endif /* __TREX_STL_PTP_H__ */