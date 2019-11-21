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

#include "trex_timesync.h"

TimesyncState CTimesyncEngine::getPortState(int port) {
    auto state = m_timesync_states.find(port);
    if (state != m_timesync_states.end()) {
        return state->second;
    } else {
        return TimesyncState::UNKNOWN;
    }
}

void CTimesyncEngine::sentAdvertisement(int port) {
    printf("MATEUSZ CTimesyncEngine::sentAdvertisement\tport=%d\tstate=%s\n", port, descTimesyncState(port));
    setPortState(port, TimesyncState::INIT);
    // TODO: S has just sent the advertisement message
}

void CTimesyncEngine::sentPTPSync(int port) {
    printf("MATEUSZ CTimesyncEngine::sentPTPSync\tport=%d\tstate=%s\n", port, descTimesyncState(port));
    setPortState(port, TimesyncState::WORK);
    // TODO: M has just sent the sync message
}

void CTimesyncEngine::sentPTPFollowUp(int port) {
    if (getPortState(port) != TimesyncState::WORK)
        return;
    printf("MATEUSZ CTimesyncEngine::sentPTPFollowUp\tport=%d\tstate=%s\n", port, descTimesyncState(port));
    // TODO: M has just sent the follow up message
}

void CTimesyncEngine::sentPTPDelayReq(int port) {
    if (getPortState(port) != TimesyncState::WORK)
        return;
    printf("MATEUSZ CTimesyncEngine::sentPTPDelayReq\tport=%d\tstate=%s\n", port, descTimesyncState(port));
    // TODO: S has just sent the delayed request message
}

void CTimesyncEngine::sentPTPDelayResp(int port) {
    if (getPortState(port) != TimesyncState::WORK)
        return;
    printf("MATEUSZ CTimesyncEngine::sentPTPDelayResp\tport=%d\tstate=%s\n", port, descTimesyncState(port));
    // TODO: M has just sent the delayed response message
    setPortState(port, TimesyncState::WAIT);
}

void CTimesyncEngine::receivedAdvertisement(int port) {
    if (getPortState(port) == TimesyncState::INIT)
        return;
    printf("MATEUSZ CTimesyncEngine::receivedAdvertisement\tport=%d\tstate=%s\n", port, descTimesyncState(port));
    setPortState(port, TimesyncState::INIT);
    // TODO: M has just got the advertisement message
}

void CTimesyncEngine::receivedPTPSync(int port) {
    if (getPortState(port) == TimesyncState::WORK)
        return;
    printf("MATEUSZ CTimesyncEngine::receivedPTPSync\tport=%d\tstate=%s\n", port, descTimesyncState(port));
    setPortState(port, TimesyncState::WORK);
    // TODO: S just got the first sync message
}

void CTimesyncEngine::receivedPTPFollowUp(int port, timespec t1) {
    if (getPortState(port) != TimesyncState::WORK)
        return;
    printf("MATEUSZ CTimesyncEngine::receivedPTPFollowUp\tport=%d\tstate=%s\tt1=%ld.%ld\n", port,
           descTimesyncState(port), t1.tv_sec, t1.tv_nsec);
    // TODO: S got the follow up message with master's t1
}

void CTimesyncEngine::receivedPTPDelayReq(int port) {
    if (getPortState(port) != TimesyncState::WORK)
        return;
    printf("MATEUSZ CTimesyncEngine::receivedPTPDelayReq\tport=%d\tstate=%s\n", port, descTimesyncState(port));
    // TODO: M got delayed request message (from slave)
}

void CTimesyncEngine::receivedPTPDelayResp(int port, timespec t4) {
    if (getPortState(port) != TimesyncState::WORK)
        return;
    printf("MATEUSZ CTimesyncEngine::receivedPTPDelayResp\tport=%d\tstate=%s\tt4=%ld.%ld\n", port,
           descTimesyncState(port), t4.tv_sec, t4.tv_nsec);
    // TODO: S just got the dealayed response message with master's t4
    setPortState(port, TimesyncState::WAIT);
}

const char *CTimesyncEngine::descTimesyncState(int port) {
    switch (getPortState(port)) {
    case TimesyncState::INIT:
        return "INIT";
    case TimesyncState::WORK:
        return "WORK";
    case TimesyncState::WAIT:
        return "WAIT";
    case TimesyncState::TERMINATE:
        return "TERMINATE";
    case TimesyncState::UNKNOWN:
        return "UNKNOWN";
    }
    return "NONE";
}
