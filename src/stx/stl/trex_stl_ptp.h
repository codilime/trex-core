#ifndef __TREX_STL_PTP_H__
#define __TREX_STL_PTP_H__

#include <cstdint>
#include <bitset>
#include <mbuf.h>
#include <rte_ether.h>

#define NSEC_PER_SEC        1000000000L
#define KERNEL_TIME_ADJUST_LIMIT  20000
#define PTP_PROTOCOL             0x88F7

namespace PTP {

/* Values for the PTP messageType field. */
enum struct message_type : uint8_t {
    // Event messages
    SYNC = 0x0,
    DELAY_REQ = 0x1,
    PDELAY_REQ = 0x2,
    PDELAY_RESP = 0x3,

    // Control messages
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

enum flag_field : uint16_t {
    PTP_LI_61 = 1 << 8,
    PTP_LI_59 = 1 << 9,
    PTP_UTC_REASONABLE = 1 << 10,
    PTP_TIMESCALE = 1 << 11,
    TIME_TRACEABLE = 1 << 12,
    FREQUENCY_TRACEABLE = 1 << 13,
    PTP_RESERVERD7 = 1 << 14,
    PTP_RESERVERD8 = 1 << 15,

    PTP_ALTERNATE_MASTER = 1 << 0,
    PTP_TWO_STEP = 1 << 1,
    PTP_UNICAST = 1 << 2,
    PTP_RESERVERD13 = 1 << 3,
    PTP_RESERVERD14 = 1 << 4,
    PTP_PROF_SPEC1 = 1 << 5,
    PTP_PROF_SPEC2 = 1 << 6,
    PTP_SECURITY = 1 << 7,

    PTP_NONE = 0
};

inline flag_field operator | (flag_field a, flag_field b) {
    return static_cast<flag_field>(static_cast<uint16_t>(a) | static_cast<uint16_t>(b));
}

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

enum struct controlField : uint8_t {
	CTL_SYNC = 0,
	CTL_DELAY_REQ = 1,
	CTL_FOLLOW_UP = 2,
	CTL_DELAY_RESP = 3,
	CTL_MANAGEMENT = 4,
	CTL_OTHER = 5,
};

struct ptp_header {
    PTP::message_type    msg_type;
    PTP::version         ver;
    PTP::message_lenght  message_length;
    PTP::domain_number   domain_number;
    uint8_t              reserved1;
    PTP::flag_field      flag_field;
    int64_t              correction;
    uint32_t             reserved2;
    PTP::port_id         source_port_id;
    uint16_t             seq_id;
    PTP::controlField    control;
    int8_t               log_message_interval;
} __attribute__((packed));

struct sync_msg {
    struct ptp_header   hdr;
    struct tstamp       origin_tstamp;
} __attribute__((packed));

struct follow_up_msg {
    struct ptp_header   hdr;
    struct tstamp       precise_origin_tstamp;
} __attribute__((packed));

struct delay_req_msg {
    struct ptp_header   hdr;
    struct tstamp       origin_tstamp;
} __attribute__((packed));

struct delay_resp_msg {
    struct ptp_header    hdr;
    struct tstamp        rx_tstamp;
    struct port_id       req_port_id;
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

    /* Prepare message */
    bool prepare_sync(rte_mbuf_t* mbuf);

    bool prepare_follow_up(rte_mbuf_t* mbuf, tstamp* t);

    bool prepare_delayed_req(rte_mbuf_t* mbuf);

    bool prepare_delayed_resp(rte_mbuf_t* mbuf, tstamp* t);

    /* Parse message */
    bool parse_sync(rte_mbuf_t* mbuf);

    bool parse_follow_up(rte_mbuf_t* mbuf, tstamp* t);

    bool parse_delayed_req(rte_mbuf_t* mbuf);

    bool parse_delayed_resp(rte_mbuf_t* mbuf);

    /* Helper methods */
    size_t pkt_size();

    int64_t delta_eval(const timespec& time1, const timespec& time2,
                       const timespec& time3, const timespec& time4);

private:
    void prepare_header(ptp_header* header, PTP::message_type type, uint16_t seq_number = 0);

    void set_port_id(PTP::port_id* port_id, struct ether_hdr* eth_hdr);

    uint64_t timespec64_to_ns(const timespec& ts);

    timeval ns_to_timeval(int64_t nsec);

    uint8_t tx_port_id;

public:
    PTPEngine(uint8_t _port_id) : tx_port_id(_port_id) {};
    PTPEngine(const PTPEngine&) = default;
    PTPEngine& operator=(const PTPEngine& other) = default;
    virtual ~PTPEngine() = default;
};

}

#endif /* __TREX_STL_PTP_H__ */