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

#include <unordered_map>

enum struct TimesyncMethod : uint8_t { NONE = 0, PTP = 1 };

enum struct TimesyncState : uint8_t { INIT = 0x31, WORK, WAIT, TERMINATE, UNKNOWN };

/**
 * Time synchronization engine
 */
class CTimesyncEngine {

  public:
    CTimesyncEngine() { m_timesync_method = TimesyncMethod::NONE; }

    inline void setTimesyncMethod(TimesyncMethod method) { m_timesync_method = method; }

    inline TimesyncMethod getTimesyncMethod() { return m_timesync_method; }

    inline void setPortState(int port, TimesyncState state) { m_timesync_states[port] = state; }

    inline TimesyncState getPortState(int port) {
        auto state = m_timesync_states.find(port);
        if (state != m_timesync_states.end()) {
            return state->second;
        } else {
            return TimesyncState::UNKNOWN;
        }
    }

    void sentAdvertisement(int port);
    void sentPTPSync(int port);
    void sentPTPFollowUp(int port);
    void sentPTPDelayReq(int port, uint64_t sent_timestamp);
    void sentPTPDelayResp(int port);

    void receivedAdvertisement(int port);
    void receivedPTPSync(int port);
    void receivedPTPFollowUp(int port, timespec t1);
    void receivedPTPDelayReq(int port);
    void receivedPTPDelayResp(int port, timespec t4);

  public:
    const char *descTimesyncState(int port);

  private:
    timespec timestampToTimespec(uint64_t timestamp);

  private:
    TimesyncMethod m_timesync_method;
    std::unordered_map<int, TimesyncState> m_timesync_states;
    timespec m_ptp_t1;
    timespec m_ptp_t2;
    timespec m_ptp_t3;
    timespec m_ptp_t4;
};

#endif /* __TREX_TIMESYNC_H__ */
