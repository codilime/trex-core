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

#include "common/Network/Packet/PTPPacket.h"

inline timespec timestampToTimespec(uint64_t timestamp) {
    return {(uint32_t)(timestamp / (1000 * 1000 * 1000)), (uint32_t)(timestamp % (1000 * 1000 * 1000))};
};

inline uint64_t timespecToTimestamp(timespec ts) { return ((uint64_t)ts.tv_sec * (1000 * 1000 * 1000)) + ts.tv_nsec; }

enum struct TimesyncMethod : uint8_t {
    NONE = 0,
    PTP = 1,
};

enum struct TimesyncTransport : uint8_t {
    ETH = 0,
    UDP = 1,
};

enum struct TimesyncCallbacks : uint8_t {
    NONE = 0,
    RX = 0b01,
    TX = 0b10,
    BOTH = 0b11
};


// A struct defining a single PTP synchronization sequence data
typedef struct {
    PTP::Field::src_port_id_field masters_source_port_id;
    PTP::Field::src_port_id_field slaves_source_port_id;
    timespec t1;
    timespec t2;
    timespec t3;
    timespec t4;
} CTimesyncPTPData_t;

// A type definition of map of sequence_id to CTimesyncPTPData_t
typedef std::unordered_map<uint16_t, CTimesyncPTPData_t> CTimesyncSequences_t;

typedef struct {
    uint16_t sequence_id;
    PTP::Field::message_type type;
    timespec time_to_send;
    PTP::Field::src_port_id_field source_port_id;
} CTimesyncPTPPacketData_t;

typedef std::queue<CTimesyncPTPPacketData_t> CTimesyncPTPPacketQueue_t;

typedef struct {
    int port;
    uint16_t sequence_id;
    uint64_t timestamp;
} CTimesyncTxTimestamp_t;


/**
 * Time synchronization engine [WIP]
 */
class CTimesyncEngine {

  public:
    CTimesyncEngine();

    void setTimesyncMethod(TimesyncMethod method) { m_timesync_method = method; }
    TimesyncMethod getTimesyncMethod() { return m_timesync_method; }

    inline void setTimesyncMaster(bool is_master) { m_is_master = is_master; }
    inline bool isTimesyncMaster() { return m_is_master; }

    // define if hardware clock on port `port` is being adjusted with PTP delta
    inline void setHardwareClockAdjusted(uint16_t port, bool is_hardware_clock_adjusted) {
        auto iter = m_hta_per_port.find(port);
        if (iter != m_hta_per_port.end()) {
            m_hta_per_port[port] = is_hardware_clock_adjusted;
        } else {
            m_hta_per_port.insert({port, is_hardware_clock_adjusted});
        }
    }
    // check if hardware clock on port `port` is being adjusted with PTP delta
    inline bool isHardwareClockAdjusted(uint16_t port) {
        try {
            return m_hta_per_port.at(port);
        } catch (const std::out_of_range &e) {
            return false;
        }
    }

    inline void setDeltaValid(uint16_t port, bool is_delta_valid) {
        auto iter = m_delta_valid_per_port.find(port);
        if (iter != m_delta_valid_per_port.end()) {
            m_delta_valid_per_port[port] = is_delta_valid;
        } else {
            m_delta_valid_per_port.insert({port, is_delta_valid});
        }
    }
    inline bool isDeltaValid(uint16_t port) {
        try {
            return m_delta_valid_per_port.at(port);
        } catch (const std::out_of_range &e) {
            return false;
        }
    }

    inline bool isSlaveSynchronized() { return m_is_slave_synchronized; }

    void setSequenceId(uint16_t sequence_id) {
        if (m_is_master)
            m_sequence_id = sequence_id;
    }
    inline uint16_t getSequenceId() {
        if (m_is_master)
            return m_sequence_id;
        else
            return 0;
    }
    inline uint16_t nextSequenceId() {
        if (m_is_master)
            return ++m_sequence_id;
        else
            return 0;
    }

    void sentPTPSync(int port, uint16_t sequence_id, timespec t);
    void sentPTPDelayReq(int port, uint16_t sequence_id, timespec t, PTP::Field::src_port_id_field source_port_id);

    void receivedPTPSync(int port, uint16_t sequence_id, timespec t, PTP::Field::src_port_id_field source_port_id);
    void receivedPTPFollowUp(int port, uint16_t sequence_id, timespec t, PTP::Field::src_port_id_field source_port_id);
    void receivedPTPDelayReq(int port, uint16_t sequence_id, timespec t, PTP::Field::src_port_id_field source_port_id);
    void receivedPTPDelayResp(int port, uint16_t seqsequence_idID, timespec t,
                              PTP::Field::src_port_id_field source_port_id,
                              PTP::Field::src_port_id_field requesting_source_port_id);

    CTimesyncPTPData_t getClockInfo(int port, uint16_t sequence_id);

    inline int64_t getDelta(int port) {
        try {
            return m_deltas.at(port);
        } catch (const std::out_of_range &e) {
            return 0;
        }
    }

    void pushNextMessage(int port, uint16_t sequence_id, PTP::Field::message_type type, timespec time,
                         PTP::Field::src_port_id_field source_port_id = {});
    CTimesyncPTPPacketData_t popNextMessage(int port);
    bool hasNextMessage(int port);

    void setTxTimestamp(int port, uint16_t sequence_id, uint64_t timestamp);
    uint8_t getTxTimestamp(int port, uint16_t sequence_id, timespec *ts);

  private:
    CTimesyncSequences_t *getSequences(int port);
    CTimesyncSequences_t *getOrCreateSequences(int port);
    CTimesyncPTPData_t *getData(int port, uint16_t sequence_id);
    CTimesyncPTPData_t *getOrCreateData(int port, uint16_t sequence_id);
    CTimesyncPTPPacketQueue_t *getPacketQueue(int port);
    CTimesyncPTPPacketQueue_t *getOrCreatePacketQueue(int port);

    int64_t evalDelta(int port, uint16_t sequence_id);
    void setDelta(int port, int64_t delta, bool *is_valid);

    bool isDataValid(CTimesyncPTPData_t *data);
    void cleanupSequencesBefore(int port, timespec t);

    bool isPacketTypeAllowed(PTP::Field::message_type type);

  private:
    TimesyncMethod m_timesync_method;
    bool m_is_master;
    bool m_is_slave_synchronized;
    uint16_t m_sequence_id;
    std::unordered_map<int, CTimesyncSequences_t> m_sequences_per_port;
    std::unordered_map<int, CTimesyncPTPPacketQueue_t> m_send_queue_per_port;
    std::unordered_map<int, int64_t> m_deltas;
    CTimesyncTxTimestamp_t m_tx_timestamp;
    std::unordered_map<int, bool> m_hta_per_port; // is hardware clock adjusting in work (per port)
    std::unordered_map<int, bool> m_delta_valid_per_port; // is recently calculated delta valid (per port)
};

#endif /* __TREX_TIMESYNC_H__ */
