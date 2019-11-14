#ifndef __TREX_STL_PTP_H__
#define __TREX_STL_PTP_H__

#include <cstdint>
#include <mbuf.h>

#define NSEC_PER_SEC        1000000000L
#define KERNEL_TIME_ADJUST_LIMIT  20000
#define PTP_PROTOCOL             0x88F7

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

    void prepare_header(ptp_header* header, PTP::message_type type, uint16_t seq_number = 0);

    /* Prepare message */
    bool prepare_sync(rte_mbuf_t* mbuf);

    bool prepare_follow_up(rte_mbuf_t* mbuf, struct tstamp* t);

    bool prepare_delayed_req(rte_mbuf_t* mbuf);

    bool prepare_delayed_resp(rte_mbuf_t* mbuf);

    /* Parse message */
    bool parse_sync(rte_mbuf_t* mbuf);

    bool parse_follow_up(rte_mbuf_t* mbuf, struct tstamp* t);

    bool parse_delayed_req(rte_mbuf_t* mbuf);

    bool parse_delayed_resp(rte_mbuf_t* mbuf);

    /* Helper methods */
    size_t pkt_size();

    void set_clock_id(struct clock_id& clock, uint8_t* new_clock);

    int64_t delta_eval(const struct timespec& time1, const struct timespec& time2,
                       const struct timespec& time3, const struct timespec& time4);

private:
    uint64_t timespec64_to_ns(const struct timespec& ts);

    struct timeval ns_to_timeval(int64_t nsec);
};

}

#endif /* __TREX_STL_PTP_H__ */