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

enum struct TimesyncMethod : uint8_t { NONE = 0, PTP = 1 };

enum struct TimesyncState : uint8_t { INIT = 0x31, WORK, WAIT, TERMINATE };

/**
 * Time synchronization engine
 */
class CTimesyncEngine {

  public:
    CTimesyncEngine() {
        m_timesync_method = TimesyncMethod::NONE;
        m_timesync_state = TimesyncState::INIT;
    }

    inline void setTimesyncMethod(TimesyncMethod method) { m_timesync_method = method; }
    inline TimesyncMethod getTimesyncMethod() { return m_timesync_method; }

    // TODO mateusz: write method that will preceed real PTP communication (a.k.a. advertisement, announcement) for PTP
    //               slave to let know PTP master of its MAC/IP.

    // TODO mateusz: write methods that are called upon receiving specific packages (i.e. PTP SYNC, PTP, FOLLOW UP etc.)

  private:
    TimesyncMethod m_timesync_method;
    TimesyncState m_timesync_state;
    timespec m_ptp_t1;
    timespec m_ptp_t2;
    timespec m_ptp_t3;
    timespec m_ptp_t4;
};

#endif /* __TREX_TIMESYNC_H__ */
