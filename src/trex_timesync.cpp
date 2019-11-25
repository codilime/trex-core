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

#include "trex_global.h"

void CTimesyncEngine::sentAdvertisement(int port) {
    printf("MATEUSZ CTimesyncEngine::sentAdvertisement\tport=%d\tstate=%s\n", port, descTimesyncState(port));
    // TODO: S has just sent the advertisement message
    setPortState(port, TimesyncState::WAIT);
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

void CTimesyncEngine::sentPTPDelayReq(int port, uint64_t sent_timestamp) {
    if (getPortState(port) != TimesyncState::WORK)
        return;
    printf("MATEUSZ CTimesyncEngine::sentPTPDelayReq\tport=%d\tstate=%s\n", port, descTimesyncState(port));
    m_ptp_t3 = timestampToTimespec(sent_timestamp);
    // TODO: S has just sent the delayed request message
    setPortState(port, TimesyncState::WAIT);
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
    m_ptp_t2 = timestampToTimespec(CGlobalInfo::m_options.get_latency_timestamp());
    if (getPortState(port) != TimesyncState::WORK) {
        m_ptp_t2 = {0, 0};
        return;
    }
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

void CTimesyncEngine::printClockInfo(struct ptpv2_data_slave_ordinary *ptp_data) {
    printf("\nT2 - Slave  Clock.  %lds %ldns",
            (ptp_data->tstamp2.tv_sec),
            (ptp_data->tstamp2.tv_nsec));

    printf("\nT1 - Master Clock.  %lds %ldns ",
            ptp_data->tstamp1.tv_sec,
            (ptp_data->tstamp1.tv_nsec));

    printf("\nT3 - Slave  Clock.  %lds %ldns",
            ptp_data->tstamp3.tv_sec,
            (ptp_data->tstamp3.tv_nsec));

    printf("\nT4 - Master Clock.  %lds %ldns ",
            ptp_data->tstamp4.tv_sec,
            (ptp_data->tstamp4.tv_nsec));

    printf("\nDelta between master and slave clocks:%"PRId64"ns\n",
        ptp_data->delta);
}

int64_t CTimesyncEngine::delta_eval(struct ptpv2_data_slave_ordinary *ptp_data) {
    int64_t delta;
    uint64_t t1 = 0;
    uint64_t t2 = 0;
    uint64_t t3 = 0;
    uint64_t t4 = 0;

    t1 = timespec64_to_ns(&ptp_data->tstamp1);
    t2 = timespec64_to_ns(&ptp_data->tstamp2);
    t3 = timespec64_to_ns(&ptp_data->tstamp3);
    t4 = timespec64_to_ns(&ptp_data->tstamp4);

    delta = -((int64_t)((t2 - t1) - (t4 - t3))) / 2;

    return delta;
}

uint64_t CTimesyncEngine::timespec64_to_ns(const struct timespec *ts){
    return ((uint64_t) ts->tv_sec * NSEC_PER_SEC) + ts->tv_nsec;
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

timespec CTimesyncEngine::timestampToTimespec(uint64_t timestamp) {
    return {(uint32_t)(timestamp / (1000 * 1000 * 1000)), (uint32_t)(timestamp % (1000 * 1000 * 1000))};
};

