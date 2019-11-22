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

enum struct TimesyncMethod : uint8_t {
    NONE = 0,
    PTP = 1,
};

// A struct defining a single PTP synchronization sequence data
typedef struct {
    timespec t1;
    timespec t2;
    timespec t3;
    timespec t4;
    timespec created_at;
} CTimesyncPTPData_t;

// A type definition of map of sequence_id to CTimesyncPTPData_t
typedef std::unordered_map<uint16_t, CTimesyncPTPData_t> CTimesyncSequences_t;

/**
 * Time synchronization engine [WIP]
 * 
 * TODO Slave should "advertise" itself
 */
class CTimesyncEngine {

  public:
    CTimesyncEngine() { m_timesync_method = TimesyncMethod::NONE; }

    void setTimesyncMethod(TimesyncMethod method) { m_timesync_method = method; }

    TimesyncMethod getTimesyncMethod() { return m_timesync_method; }

    void setTimesyncMaster(bool is_master) { m_is_master = is_master; }

    bool isTimesyncMaster() { return m_is_master; }

    // void sentAdvertisement(int port);
    // void sentPTPSync(int port);
    // void sentPTPFollowUp(int port);
    // void sentPTPDelayReq(int port, uint64_t sent_timestamp);
    // void sentPTPDelayResp(int port);

    // void receivedAdvertisement(int port);
    void receivedPTPSync(int port, uint16_t sequence_id, timespec t2);
    void receivedPTPFollowUp(int port, uint16_t sequence_id, timespec t1);
    // void receivedPTPDelayReq(int port);
    void receivedPTPDelayResp(int port, uint16_t sequence_id, timespec t4);

  private:
    TimesyncMethod m_timesync_method;
    bool m_is_master;
    std::unordered_map<int, CTimesyncSequences_t> m_sequences_per_port;

  private:
    CTimesyncSequences_t getOrCreateSequences(int port);
    CTimesyncPTPData_t getOrCreateData(CTimesyncSequences_t sequences, uint16_t sequence_id);
    CTimesyncPTPData_t getOrCreateData(int port, uint16_t sequence_id);
};

#endif /* __TREX_TIMESYNC_H__ */
