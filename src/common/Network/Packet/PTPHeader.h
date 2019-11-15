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

#ifndef _PTP_HEADER_H_
#define _PTP_HEADER_H_

#include <type_traits>

#include "CPktCmn.h"

#define PTP_HDR_LEN 34

#define PTP_MSG_SYNC_LEN 10
#define PTP_MSG_FOLLOWUP_LEN 10
#define PTP_MSG_DELAYREQ_LEN 10
#define PTP_MSG_DELAYRESP_LEN 20

class PTPHeader {

  public:
    struct MessageType {
        enum Type { SYNC = 0, DELAY_REQ = 1, FOLLOW_UP = 8, DELAY_RESP = 9 };
        static char *interpretMessageType(uint8_t messageType);
    };

    struct Flags {
        enum Type {
            SECURITY = 0x8000,
            PROFILE_SPEC_2 = 0x4000,
            PROFILE_SPEC_1 = 0x2000,
            UNICAST = 0x0400,
            TWO_STEP = 0x0200,
            ALTERNNATIVE_MASTER = 0x0100,
            FREQUENCY_TRACEABLE = 0x0020,
            TIME_TRACEABLE = 0x0010,
            TIMESCALE = 0x0008,
            UTC_REASONABLE = 0x0004,
            LI_59 = 0x0002,
            LI_61 = 0x0001,
        };
    };

    inline uint8_t getTransportSpecific() { return transportSpec_messageId >> 4; }
    inline uint8_t getMessageId() { return transportSpec_messageId & 0x0F; }
    inline uint8_t getVersion() { return version; }
    inline uint16_t getLength() { return PKT_NTOHS(length); }
    inline uint8_t getSubdomainNumber() { return subdomainNumber; }
    inline uint16_t getFlags() { return PKT_NTOHS(flags); }
    inline uint64_t getCorrection() { return PKT_NTOHLL(correction); }
    inline uint64_t getClockIdentity() { return PKT_NTOHLL(clockIdentity); }
    inline uint16_t getSourcePortId() { return PKT_NTOHS(sourcePortId); }
    inline uint16_t getSequenceId() { return PKT_NTOHS(sequenceId); }
    inline uint8_t getControl() { return control; }
    inline uint8_t getLogMessagePeriod() { return logMessagePeriod; }

    inline bool isTwoStep() {return getFlags() & Flags::TWO_STEP; }

    void dump(FILE *fd);

  private:
    uint8_t transportSpec_messageId;
    uint8_t version;
    uint16_t length;
    uint8_t subdomainNumber;
    uint8_t reserved_0;
    uint16_t flags;
    uint64_t correction;
    uint32_t reserved_1;
    uint64_t clockIdentity;
    uint16_t sourcePortId;
    uint16_t sequenceId;
    uint8_t control;
    uint8_t logMessagePeriod;
};

static_assert(std::is_standard_layout<PTPHeader>::value, "PTPHeader must be a simple linear data structure.");

#endif
