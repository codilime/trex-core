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

void dumpTimesyncPTPData(FILE *fd, CTimesyncPTPData_t data) {
    fprintf(fd, "MATEUSZ dumpTimesyncPTPData\tt1=%ld.%ld\tt2=%ld.%ld\tt3=%ld.%ld\tt4=%ld.%ld\n", data.t1.tv_sec,
            data.t1.tv_nsec, data.t2.tv_sec, data.t2.tv_nsec, data.t3.tv_sec, data.t3.tv_nsec, data.t4.tv_sec,
            data.t4.tv_nsec);
}

timespec timestampToTimespec(uint64_t timestamp) {
    return {(uint32_t)(timestamp / (1000 * 1000 * 1000)), (uint32_t)(timestamp % (1000 * 1000 * 1000))};
};

uint64_t timespecToTimestamp(const timespec *ts){
    return ((uint64_t) ts->tv_sec * (1000 * 1000 * 1000)) + ts->tv_nsec;
}

/**
 * CTimesyncEngine
 */

//////////////////////////////////////////////////////////////////

// void CTimesyncEngine::sentAdvertisement(int port) {
//     printf("MATEUSZ CTimesyncEngine::sentAdvertisement\tport=%d\tstate=%s\n", port, descTimesyncState(port));
//     // TODO: S has just sent the advertisement message
//     setPortState(port, TimesyncState::WAIT);
// }

// void CTimesyncEngine::sentPTPSync(int port) {
//     printf("MATEUSZ CTimesyncEngine::sentPTPSync\tport=%d\tstate=%s\n", port, descTimesyncState(port));
//     setPortState(port, TimesyncState::WORK);
//     // TODO: M has just sent the sync message
// }

// void CTimesyncEngine::sentPTPFollowUp(int port) {
//     if (getPortState(port) != TimesyncState::WORK)
//         return;
//     printf("MATEUSZ CTimesyncEngine::sentPTPFollowUp\tport=%d\tstate=%s\n", port, descTimesyncState(port));
//     // TODO: M has just sent the follow up message
// }

// void CTimesyncEngine::sentPTPDelayReq(int port, uint64_t sent_timestamp) {
//     if (getPortState(port) != TimesyncState::WORK)
//         return;
//     printf("MATEUSZ CTimesyncEngine::sentPTPDelayReq\tport=%d\tstate=%s\n", port, descTimesyncState(port));
//     m_ptp_t3 = timestampToTimespec(sent_timestamp);
//     // TODO: S has just sent the delayed request message
//     setPortState(port, TimesyncState::WAIT);
// }

// void CTimesyncEngine::sentPTPDelayResp(int port) {
//     if (getPortState(port) != TimesyncState::WORK)
//         return;
//     printf("MATEUSZ CTimesyncEngine::sentPTPDelayResp\tport=%d\tstate=%s\n", port, descTimesyncState(port));
//     // TODO: M has just sent the delayed response message
//     setPortState(port, TimesyncState::WAIT);
// }

// void CTimesyncEngine::receivedAdvertisement(int port) {
//     if (getPortState(port) == TimesyncState::INIT)
//         return;
//     printf("MATEUSZ CTimesyncEngine::receivedAdvertisement\tport=%d\tstate=%s\n", port, descTimesyncState(port));
//     setPortState(port, TimesyncState::INIT);
//     // TODO: M has just got the advertisement message
// }

void CTimesyncEngine::receivedPTPSync(int port, uint16_t sequence_id, timespec t2) {
    CTimesyncPTPData_t data = getOrCreateData(port, sequence_id);
    data.t2 = t2;
    m_sequences_per_port[port][sequence_id] = data;
}

void CTimesyncEngine::receivedPTPFollowUp(int port, uint16_t sequence_id, timespec t1) {
    CTimesyncPTPData_t data = getOrCreateData(port, sequence_id);
    data.t1 = t1;
    m_sequences_per_port[port][sequence_id] = data;
    // TODO send delay request with with sequence ID = sequence_id
}

void CTimesyncEngine::receivedPTPDelayReq(int port, uint16_t sequence_id, timespec t4) {
    //TODO send delay response with timestamp = t4, sequence ID = sequence_id
}

void CTimesyncEngine::receivedPTPDelayResp(int port, uint16_t sequence_id, timespec t4) {
    CTimesyncPTPData_t data = getOrCreateData(port, sequence_id);
    data.t4 = t4;
    m_sequences_per_port[port][sequence_id] = data;
    dumpTimesyncPTPData(stdout, data);
    delta_eval(port, sequence_id);
    printClockInfo(port, sequence_id);
}

// const char *CTimesyncEngine::descTimesyncState(int port) {
//     switch (getPortState(port)) {
//     case TimesyncState::INIT:
//         return "INIT";
//     case TimesyncState::WORK:
//         return "WORK";
//     case TimesyncState::WAIT:
//         return "WAIT";
//     case TimesyncState::TERMINATE:
//         return "TERMINATE";
//     case TimesyncState::UNKNOWN:
//         return "UNKNOWN";
//     }
//     return "NONE";
// }

CTimesyncSequences_t CTimesyncEngine::getOrCreateSequences(int port) {
    CTimesyncSequences_t sequences;
    try {
        sequences = m_sequences_per_port.at(port);
    } catch (const std::out_of_range &e) {
        sequences = CTimesyncSequences_t();
        m_sequences_per_port.insert({port, sequences});
    }
    return sequences;
}

CTimesyncPTPData_t CTimesyncEngine::getOrCreateData(CTimesyncSequences_t sequences, uint16_t sequence_id) {
    CTimesyncPTPData_t ptp_data;
    try {
        ptp_data = sequences.at(sequence_id);
    } catch (const std::out_of_range &e) {
        ptp_data = CTimesyncPTPData_t();
        sequences.insert({sequence_id, ptp_data});
    }
    return ptp_data;
}

CTimesyncPTPData_t CTimesyncEngine::getOrCreateData(int port, uint16_t sequence_id) {
    return getOrCreateData(getOrCreateSequences(port), sequence_id);
}

void CTimesyncEngine::printClockInfo(int port, uint16_t sequence_id) {
    CTimesyncPTPData_t data = getOrCreateData(port, sequence_id);

    printf("\nT1 - Master Clock.  %lds %ldns ",
            data.t1.tv_sec,
            (data.t1.tv_nsec));

    printf("\nT2 - Slave  Clock.  %lds %ldns",
            (data.t2.tv_sec),
            (data.t2.tv_nsec));

    printf("\nT3 - Slave  Clock.  %lds %ldns",
            data.t3.tv_sec,
            (data.t3.tv_nsec));

    printf("\nT4 - Master Clock.  %lds %ldns ",
            data.t4.tv_sec,
            (data.t4.tv_nsec));

    printf("\nDelta between master and slave clocks:%ldns\n",
        data.delta);
}

void CTimesyncEngine::delta_eval(int port, uint16_t sequence_id) {
    CTimesyncPTPData_t data = getOrCreateData(port, sequence_id);
    uint64_t t1 = 0;
    uint64_t t2 = 0;
    uint64_t t3 = 0;
    uint64_t t4 = 0;

    t1 = timespecToTimestamp(&data.t1);
    t2 = timespecToTimestamp(&data.t2);
    t3 = timespecToTimestamp(&data.t3);
    t4 = timespecToTimestamp(&data.t4);

    data.delta = -((int64_t)((t2 - t1) - (t4 - t3))) / 2;

    m_sequences_per_port[port][sequence_id] = data;
}
