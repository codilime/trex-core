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
    printf("MATEUSZ CTimesyncEngine::receivedPTPSync\tport=%d\tsequence_id=%d\tt2=%ld.%ld\n", port, sequence_id,
           t2.tv_sec, t2.tv_nsec);
    CTimesyncPTPData_t data = getOrCreateData(port, sequence_id);
    data.t2 = t2;
    m_sequences_per_port[port][sequence_id] = data;
}

void CTimesyncEngine::receivedPTPFollowUp(int port, uint16_t sequence_id, timespec t1) {
    printf("MATEUSZ CTimesyncEngine::receivedPTPFollowUp\tport=%d\tsequence_id=%d\tt1=%ld.%ld\n", port, sequence_id,
           t1.tv_sec, t1.tv_nsec);
    CTimesyncPTPData_t data = getOrCreateData(port, sequence_id);
    data.t1 = t1;
    m_sequences_per_port[port][sequence_id] = data;

    // TODO mateusz prepare data for the sending queue
}

// void CTimesyncEngine::receivedPTPDelayReq(int port) {
//     if (getPortState(port) != TimesyncState::WORK)
//         return;
//     printf("MATEUSZ CTimesyncEngine::receivedPTPDelayReq\tport=%d\tstate=%s\n", port, descTimesyncState(port));
//     // TODO: M got delayed request message (from slave)
// }

void CTimesyncEngine::receivedPTPDelayResp(int port, uint16_t sequence_id, timespec t4) {
    printf("MATEUSZ CTimesyncEngine::receivedPTPDelayResp\tport=%d\tsequence_id=%d\tt4=%ld.%ld\n", port, sequence_id,
           t4.tv_sec, t4.tv_nsec);
    CTimesyncPTPData_t data = getOrCreateData(port, sequence_id);
    data.t4 = t4;
    m_sequences_per_port[port][sequence_id] = data;
    dumpTimesyncPTPData(stdout, data);
}
// void CTimesyncEngine::receivedPTPDelayResp(int port, timespec t4) {
//     CTimesyncSlaveEngine *slave_engine = getSlaveEngine(port);
//     if (slave_engine->isValidTransition(TimesyncSlaveSyncState::FOLLOWUP_RECEIVED)) {
//         printf("MATEUSZ CTimesyncEngine::receivedPTPDelayResp\tport=%d\tVALID STATE\n", port);
//         slave_engine->setSyncState(TimesyncSlaveSyncState::FOLLOWUP_RECEIVED);
//     } else {
//         printf("MATEUSZ CTimesyncEngine::receivedPTPDelayResp\tport=%d\tINVALID STATE\n", port);
//     }
//     // TODO: S just got the dealayed response message with master's t4
// }

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
