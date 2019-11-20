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

#define PTP_MSG_SYNC_LEN 10
#define PTP_MSG_FOLLOWUP_LEN 10
#define PTP_MSG_DELAYREQ_LEN 10
#define PTP_MSG_DELAYRESP_LEN 20

struct PTPPacket {

  public:
    inline uint16_t getOriginSecondsMsb() { return PKT_NTOHS(originSecondsMsb); }
    inline uint32_t getOriginSecondsLsb() { return PKT_NTOHL(originSecondsLsb); }
    inline uint32_t getOriginNanoseconds() { return PKT_NTOHL(originNanoseconds); }
    inline double getOriginTimestamp() {
        return (double)((uint64_t)(getOriginSecondsMsb()) << 32) + (double)getOriginSecondsLsb() +
               (double)(getOriginNanoseconds()) / 1000.0 / 1000.0 / 1000.0;
    }

    void dump(FILE *fd);

  private:
    uint16_t originSecondsMsb;
    uint32_t originSecondsLsb;
    uint32_t originNanoseconds;
} __attribute__((packed));

static_assert(std::is_standard_layout<PTPPacket>::value, "PTPPacket must be a simple linear data structure.");

struct PTPPacketSync : PTPPacket {};
static_assert(std::is_standard_layout<PTPPacketSync>::value, "PTPPacketSync must be a simple linear data structure.");

struct PTPPacketFollowUp : PTPPacket {};
static_assert(std::is_standard_layout<PTPPacketFollowUp>::value,
              "PTPPacketFollowUp must be a simple linear data structure.");

struct PTPPacketDelayedReq : PTPPacket {};
static_assert(std::is_standard_layout<PTPPacketDelayedReq>::value,
              "PTPPacketDelayedReq must be a simple linear data structure.");

struct PTPPacketDelayedResp {
  public:
    inline uint16_t getOriginSecondsMsb() { return PKT_NTOHS(originSecondsMsb); }
    inline uint32_t getOriginSecondsLsb() { return PKT_NTOHL(originSecondsLsb); }
    inline uint32_t getOriginNanoseconds() { return PKT_NTOHL(originNanoseconds); }
    inline double getOriginTimestamp() {
        return (double)((uint64_t)(getOriginSecondsMsb()) << 32) + (double)getOriginSecondsLsb() +
               (double)(getOriginNanoseconds()) / 1000.0 / 1000.0 / 1000.0;
    }
    inline uint64_t getReqClockIdentity() { return PKT_NTOHLL(reqClockIdentity); }
    inline uint16_t getReqSourcePortId() { return PKT_NTOHS(reqSourcePortId); }

    void dump(FILE *fd);

  private:
    uint16_t originSecondsMsb;
    uint32_t originSecondsLsb;
    uint32_t originNanoseconds;
    uint64_t reqClockIdentity;
    uint16_t reqSourcePortId;
} __attribute__((packed));

static_assert(std::is_standard_layout<PTPPacketDelayedResp>::value,
              "PTPPacketDelayedResp must be a simple linear data structure.");

#endif
