/*
 Mateusz Neumann
 Codilime Sp. z o.o.
*/

/*
Copyright (c) 2019 Codilime Sp. z o.o.

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

#ifndef __TREX_TIMESYNC_H__
#define __TREX_TIMESYNC_H__

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <unordered_map>
#include <queue>

enum struct TimesyncMethod : uint8_t {
    NONE = 0,
    PTP = 1,
};

enum struct TimesyncPacketType : uint8_t {
    PTP_SYNC = 0x00,
    PTP_FOLLOWUP = 0x08,
    PTP_DELAYREQ = 0x01,
    PTP_DELAYRESP = 0x09,
    UNKNOWN = 0x0F,
};

// A struct defining a single PTP synchronization sequence data
typedef struct {
    timespec t1;
    timespec t2;
    timespec t3;
    timespec t4;
} CTimesyncPTPData_t;

// A type definition of map of sequence_id to CTimesyncPTPData_t
typedef std::unordered_map<uint16_t, CTimesyncPTPData_t> CTimesyncSequences_t;

// struct NextMessage {
//     TimesyncPacketType type;
//     uint16_t  seq_id;
//     timespec  time_to_send;
// };
typedef struct {
    uint16_t sequence_id;
    TimesyncPacketType type;
    timespec time_to_send;
} CTimesyncPTPPacketData_t;

typedef std::queue<CTimesyncPTPPacketData_t> CTimesyncPTPPacketQueue_t;

/**
 * Time synchronization engine [WIP]
 */
class CTimesyncEngine {

  public:
    CTimesyncEngine();

    void setTimesyncMethod(TimesyncMethod method) { m_timesync_method = method; }
    TimesyncMethod getTimesyncMethod() { return m_timesync_method; }

    void setTimesyncMaster(bool is_master) { m_is_master = is_master; }
    bool isTimesyncMaster() { return m_is_master; }

    void setSequenceId(uint16_t sequence_id) {
        if (m_is_master)
            m_sequence_id = sequence_id;
    }
    uint16_t getSequenceId() {
        if (m_is_master)
            return m_sequence_id;
        else
            return 0;
    }
    uint16_t nextSequenceId() {
        if (m_is_master)
            return ++m_sequence_id;
        else
            return 0;
    }


    void sentPTPSync(int port, uint16_t sequence_id, timespec t);      // master
    void sentPTPFollowUp(int port, uint16_t sequence_id, timespec t);  // master
    void sentPTPDelayReq(int port, uint16_t sequence_id, timespec t);  // slave
    void sentPTPDelayResp(int port, uint16_t sequence_id, timespec t); // master

    void receivedPTPSync(int port, uint16_t sequence_id, timespec t);           // slave
    void receivedPTPFollowUp(int port, uint16_t sequence_id, timespec t);       // slave
    void receivedPTPDelayReq(int port, uint16_t sequence_id, timespec t);       // master
    void receivedPTPDelayResp(int port, uint16_t seqsequence_idID, timespec t); // slave

    int64_t evalDelta(int port, uint16_t sequence_id);
    void setDelta(int port, int64_t delta);
    int64_t getDelta(int port);

    void pushNextMessage(int port, uint16_t sequence_id, TimesyncPacketType type, timespec time);
    CTimesyncPTPPacketData_t popNextMessage(int port);
    bool hasNextMessage(int port);

/*
    bool isNextMessage(uint8_t port_id) {
      return !(m_per_port_send_queue[port_id].empty());
    }

    NextMessage getNextMessage(uint8_t port_id){
      NextMessage& next_message = m_per_port_send_queue[port_id].front();
      m_per_port_send_queue[port_id].pop();
      return next_message;
    }

    void pushNextMessage(uint8_t port_id, const TimesyncPacketType& type, const timespec& time = {0, 0}){
      m_per_port_send_queue[port_id].emplace(type, ++last_seq_id, time);
    }
    */

  private:
    CTimesyncSequences_t *getSequences(int port);
    CTimesyncSequences_t *getOrCreateSequences(int port);
    CTimesyncPTPData_t *getData(int port, uint16_t sequence_id);
    CTimesyncPTPData_t *getOrCreateData(int port, uint16_t sequence_id);
    CTimesyncPTPPacketQueue_t *getPacketQueue(int port);
    CTimesyncPTPPacketQueue_t *getOrCreatePacketQueue(int port);

    bool isDataValid(CTimesyncPTPData_t *data);
    void cleanupSequencesBefore(int port, timespec t);

  private:
    TimesyncMethod m_timesync_method;
    bool m_is_master;
    uint16_t m_sequence_id;
    std::unordered_map<int, CTimesyncSequences_t> m_sequences_per_port;
    std::unordered_map<int, CTimesyncPTPPacketQueue_t> m_send_queue_per_port;
    std::unordered_map<int, int64_t> m_deltas;
};

#endif /* __TREX_TIMESYNC_H__ */
