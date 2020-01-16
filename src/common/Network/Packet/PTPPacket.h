/*
Copyright (c) 2019 Mateusz Neumann, Codilime

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

#ifndef _PTP_PACKET_H_
#define _PTP_PACKET_H_

#include <type_traits>

#include "CPktCmn.h"

#define PTP_HDR_LEN 34

#define PTP_MSG_BASE_LEN 10
#define PTP_MSG_SYNC_LEN PTP_MSG_BASE_LEN
#define PTP_MSG_FOLLOWUP_LEN PTP_MSG_BASE_LEN
#define PTP_MSG_DELAYREQ_LEN PTP_MSG_BASE_LEN
#define PTP_MSG_DELAYRESP_LEN (PTP_MSG_BASE_LEN + 10)

#define PTP_SYNC_LEN (PTP_HDR_LEN + PTP_MSG_SYNC_LEN)
#define PTP_FOLLOWUP_LEN (PTP_HDR_LEN + PTP_MSG_FOLLOWUP_LEN)
#define PTP_DELAYREQ_LEN (PTP_HDR_LEN + PTP_MSG_DELAYREQ_LEN)
#define PTP_DELAYRESP_LEN (PTP_HDR_LEN + PTP_MSG_DELAYRESP_LEN)

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

namespace PTP {

namespace Field{

template<typename T>
struct net_field8{
    T value;

    net_field8& operator=(const T& val){
        value = val;
        return *this;
    }

    T operator*(){
        return value;
    }
} __attribute__((packed));
typedef net_field8<uint8_t> net_field8_t;

template<typename T>
struct net_field16{
    T value;

    net_field16& operator=(const T& val){
        value = PKT_HTONS(val);
        return *this;
    }

    T operator*(){
        return PKT_NTOHS(value);
    }
} __attribute__((packed));
typedef net_field16<uint16_t> net_field16_t;

template<typename T>
struct net_field32{
    T value;

    net_field32& operator=(const T& val){
        value = PKT_HTONL(val);
        return *this;
    }

    T operator*(){
        return PKT_NTOHL(value);
    }
} __attribute__((packed));
typedef net_field32<uint32_t> net_field32_t;

enum struct transport_specific : uint8_t  {
    DEFAULT = 0x0,
    ETH_AVB = 0x1
};

/* Values for the PTP messageType field. */
enum struct message_type : uint8_t {
    // Event messages
    SYNC                    = 0x0,
    DELAY_REQ               = 0x1,
    PDELAY_REQ              = 0x2,
    PDELAY_RESP             = 0x3,

    // Control messages
    FOLLOW_UP               = 0x8,
    DELAY_RESP              = 0x9,
    PDELAY_RESP_FOLLOW_UP   = 0xA,
    ANNOUNCE                = 0xB,
    SIGNALING               = 0xC,
    MANAGEMENT              = 0xD,
    // When something goes wrong 
    UNKNOWN                 = 0xF,
};

struct trans_spec_and_mess_type{
    uint8_t _mess_type : 4;
    uint8_t _trans_spec : 4;

    trans_spec_and_mess_type & operator=(const message_type & a) {
        _mess_type = static_cast<std::underlying_type<message_type>::type>(a);
        return *this;
    };

    trans_spec_and_mess_type & operator=(const transport_specific & a) {
        _trans_spec = static_cast<std::underlying_type<transport_specific>::type>(a);
        return *this;
    };

    transport_specific trans_spec() {
        return static_cast<transport_specific>(_trans_spec);
    };

    uint8_t trans_spec_raw() {
        return _trans_spec;
    };

    message_type msg_type() {
        return static_cast<message_type>(_mess_type);
    };

    uint8_t msg_type_raw() {
        return _mess_type;
    };

    const char * msg_type_str() {
        switch (msg_type()) {
        case message_type::SYNC:
            return "SYNC";
        case message_type::DELAY_REQ:
            return "DELAY_REQ";
        case message_type::PDELAY_REQ:
            return "PDELAY_REQ";
        case message_type::PDELAY_RESP:
            return "PDELAY_RESP";
        case message_type::FOLLOW_UP:
            return "FOLLOW_UP";
        case message_type::DELAY_RESP:
            return "DELAY_RESP";
        case message_type::PDELAY_RESP_FOLLOW_UP:
            return "PDELAY_RESP_FOLLOW_UP";
        case message_type::ANNOUNCE:
            return "ANNOUNCE";
        case message_type::SIGNALING:
            return "SIGNALING";
        case message_type::MANAGEMENT:
            return "MANAGEMENT";
        default:
            return (const char *)"UNKNOWN";
        }
    }
} __attribute__((packed));

enum struct version : uint8_t {
    PTPv1 = 0x1,
    PTPv2 = 0x2
};

typedef net_field8<version> version_field;
typedef net_field16_t message_length_field;
typedef net_field8_t domain_number_field;

enum flags : uint16_t {
    PTP_NONE                = 0,
    PTP_LI_61               = 1 << 0,
    PTP_LI_59               = 1 << 1,
    PTP_UTC_REASONABLE      = 1 << 2,
    PTP_TIMESCALE           = 1 << 3,
    TIME_TRACEABLE          = 1 << 4,
    FREQUENCY_TRACEABLE     = 1 << 5,
    PTP_RESERVERD7          = 1 << 6,
    PTP_RESERVERD8          = 1 << 7,

    PTP_ALTERNATE_MASTER    = 1 << 8,
    PTP_TWO_STEP            = 1 << 9,
    PTP_UNICAST             = 1 << 10,
    PTP_RESERVERD13         = 1 << 11,
    PTP_RESERVERD14         = 1 << 12,
    PTP_PROF_SPEC1          = 1 << 13,
    PTP_PROF_SPEC2          = 1 << 14,
    PTP_SECURITY            = 1 << 15,
};

inline flags operator | (const flags& a, const flags& b) {
    return static_cast<flags>(static_cast<std::underlying_type<flags>::type>(a) | static_cast<std::underlying_type<flags>::type>(b));
}

struct flag_field {
    uint16_t value;

    flag_field& operator=(const uint16_t& val){
        value = PKT_HTONS(val);
        return *this;
    }

    flag_field& operator=(const flags& val){
        value = PKT_HTONS(static_cast<std::underlying_type<flags>::type>(val));
        return *this;
    }

    flag_field& operator|=(const flags& val){
        value |= PKT_HTONS(static_cast<std::underlying_type<flags>::type>(val));
        return *this;
    }

    flag_field& operator&=(const flags& val){
        value &= PKT_HTONS(static_cast<std::underlying_type<flags>::type>(val));
        return *this;
    }

    uint16_t get(){
        return PKT_NTOHS(static_cast<std::underlying_type<flags>::type>(value));
    }

    flags operator*(){
        return static_cast<flags>(get());
    }
} __attribute__((packed));

struct correction_field{
    int64_t value;

    correction_field& operator=(const int64_t& val){
        value = PKT_HTONLL(val);
        return *this;
    }

    uint64_t operator*(){
        return PKT_NTOHLL(value);
    }
} __attribute__((packed));

template<typename T>
struct reserved_field {
    T value;
} __attribute__((packed));

union clock_id_field{
    uint8_t    b[8];
    uint64_t   l;
} __attribute__((packed));

struct src_port_id_field {
    clock_id_field _clock_id;
    uint16_t       _port_number;

    uint64_t clock_id(){
        return PKT_NTOHLL(_clock_id.l);
    }

    uint16_t port_number(){
        return PKT_NTOHS(_port_number);
    }

    bool operator==(const src_port_id_field &other) {
        return (_clock_id.l == other._clock_id.l) && (_port_number == other._port_number);
    }

    bool operator!=(const src_port_id_field &other) { return !(*this == other); }

} __attribute__((packed));

typedef net_field16_t sequence_id_field;

enum struct control : uint8_t {
    CTL_SYNC = 0,
    CTL_DELAY_REQ = 1,
    CTL_FOLLOW_UP = 2,
    CTL_DELAY_RESP = 3,
    CTL_MANAGEMENT = 4,
    CTL_OTHER = 5,
};

typedef net_field8<control> control_field;

typedef net_field8<int8_t> log_msg_interval_field;

struct tstamp_field {
    net_field16_t   sec_msb;
    net_field32_t   sec_lsb;
    net_field32_t   ns;

    inline timespec get_timestamp() {
        return { *sec_lsb, *ns };
    }
} __attribute__((packed));

}

struct Header {
    Field::trans_spec_and_mess_type trn_and_msg;
    Field::version_field            ver;
    Field::message_length_field     message_len;
    Field::domain_number_field      domain_number;
    Field::reserved_field<uint8_t>  reserved1;
    Field::flag_field               flag_field;
    Field::correction_field         correction;
    Field::reserved_field<uint32_t> reserved2;
    Field::src_port_id_field        source_port_id;
    Field::sequence_id_field        seq_id;
    Field::control_field            control;
    Field::log_msg_interval_field   log_message_interval;

    void dump(FILE *fd);
} __attribute__((packed));

static_assert(std::is_standard_layout<Header>::value,
              "PTP::Header must be a simple linear data structure.");
static_assert(sizeof(Header) == PTP_HDR_LEN,
              "PTP::Header must have exactly " STR(PTP_HDR_LEN) ".");

struct BasePacket {
    Field::tstamp_field origin_timestamp;

    void dump(FILE *fd);
} __attribute__((packed));
static_assert(std::is_standard_layout<BasePacket>::value,
              "PTP::BasePacket must be a simple linear data structure.");
static_assert(sizeof(BasePacket) == PTP_MSG_BASE_LEN,
              "PTP::BasePacket must have exactly " STR(PTP_MSG_BASE_LEN) ".");

struct SyncPacket : BasePacket {
    static constexpr size_t size = PTP_MSG_SYNC_LEN;
    static constexpr Field::message_type type = Field::message_type::SYNC;
};
static_assert(std::is_standard_layout<SyncPacket>::value,
              "PTP::SyncPacket must be a simple linear data structure.");
static_assert(sizeof(SyncPacket) == PTP_MSG_SYNC_LEN,
              "PTP::SyncPacket must have exactly " STR(PTP_MSG_SYNC_LEN) ".");

struct FollowUpPacket : BasePacket {
    static constexpr size_t size = PTP_MSG_FOLLOWUP_LEN;
    static constexpr Field::message_type type = Field::message_type::FOLLOW_UP;
};
static_assert(std::is_standard_layout<FollowUpPacket>::value,
              "PTP::FollowUpPacket must be a simple linear data structure.");
static_assert(sizeof(FollowUpPacket) == PTP_MSG_FOLLOWUP_LEN, 
              "PTP::FollowUpPacket must have exactly " STR(PTP_MSG_FOLLOWUP_LEN) ".");

struct DelayedReqPacket : BasePacket {
    static constexpr size_t size = PTP_MSG_DELAYREQ_LEN;
    static constexpr Field::message_type type = Field::message_type::PDELAY_REQ;
};
static_assert(std::is_standard_layout<DelayedReqPacket>::value,
              "PTP::DelayedReqPacket must be a simple linear data structure.");
static_assert(sizeof(DelayedReqPacket) == PTP_MSG_DELAYREQ_LEN, 
              "PTP::DelayedReqPacket must have exactly " STR(PTP_MSG_DELAYREQ_LEN) ".");

struct DelayedRespPacket {
    Field::tstamp_field origin_timestamp;
    Field::src_port_id_field req_clock_identity;

    void dump(FILE *fd);

    static constexpr size_t size = PTP_MSG_DELAYRESP_LEN;
    static constexpr Field::message_type type = Field::message_type::DELAY_RESP;
};
static_assert(std::is_standard_layout<DelayedRespPacket>::value,
              "PTP::DelayedRespPacket must be a simple linear data structure.");
static_assert(sizeof(DelayedRespPacket) == PTP_MSG_DELAYRESP_LEN,
              "PTP::DelayedRespPacket must have exactly " STR(PTP_MSG_DELAYRESP_LEN) ".");

}

#endif
