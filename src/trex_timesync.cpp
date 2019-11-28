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

inline timespec timestampToTimespec(uint64_t timestamp) {
    return {(uint32_t)(timestamp / (1000 * 1000 * 1000)), (uint32_t)(timestamp % (1000 * 1000 * 1000))};
};

inline uint64_t timespecToTimestamp(timespec ts) { return ((uint64_t)ts.tv_sec * (1000 * 1000 * 1000)) + ts.tv_nsec; }

/**
 * CTimesyncEngine
 */

CTimesyncEngine::CTimesyncEngine() { m_timesync_method = TimesyncMethod::NONE; }

// PTP Slave's code //////////////////////////////////////////////

// slave flow: receive SYNC, receive FOLLOW_UP, send DELAY_REQ, receive DELAY_RESP

void CTimesyncEngine::receivedPTPSync(int port, uint16_t sequence_id, timespec t) {
    if (m_is_master)
        return;
    CTimesyncPTPData_t *data = getOrCreateData(port, sequence_id);
    data->t2 = t;
}

void CTimesyncEngine::receivedPTPFollowUp(int port, uint16_t sequence_id, timespec t) {
    if (m_is_master)
        return;
    CTimesyncPTPData_t *data = getData(port, sequence_id);
    if (data == nullptr)
        return;
    data->t1 = t;
    pushNextMessage(port, sequence_id, TimesyncPacketType::PTP_DELAYREQ, {0, 0});
}

void CTimesyncEngine::sentPTPDelayReq(int port, uint16_t sequence_id, timespec t) {
    if (m_is_master)
        return;
    CTimesyncPTPData_t *data = getData(port, sequence_id);
    if (data == nullptr)
        return;
    data->t3 = t;
}

void CTimesyncEngine::receivedPTPDelayResp(int port, uint16_t sequence_id, timespec t) {
    if (m_is_master)
        return;
    CTimesyncPTPData_t *data = getData(port, sequence_id);
    if (data == nullptr)
        return;
    data->t4 = t;
    evalDelta(port, sequence_id);
}

// PTP Master's code /////////////////////////////////////////////

// master flow: send SYNC, send FOLLOW_UP, receive DELAY_REQ, send DELAY_RESP

void CTimesyncEngine::sentPTPSync(int port, uint16_t sequence_id, timespec t) {
    if (!m_is_master)
        return;
    pushNextMessage(port, sequence_id, TimesyncPacketType::PTP_FOLLOWUP, t);
}

void CTimesyncEngine::sentPTPFollowUp(int port, uint16_t sequence_id, timespec t) {
    if (!m_is_master)
        return;
    // wait for the Delay Resp packet
}

void CTimesyncEngine::receivedPTPDelayReq(int port, uint16_t sequence_id, timespec t) {
    if (!m_is_master)
        return;
    pushNextMessage(port, sequence_id, TimesyncPacketType::PTP_DELAYRESP, t);
}

void CTimesyncEngine::sentPTPDelayResp(int port, uint16_t sequence_id, timespec t) {
    if (!m_is_master)
        return;
    // be done
}

// Delta calculations and handling ///////////////////////////////

void CTimesyncEngine::cleanupSequencesBefore(int port, timespec ts) {
    if (timespecToTimestamp(ts) <= 0)
        return;
    uint64_t timestamp = timespecToTimestamp(ts);
    CTimesyncSequences_t sequences = m_sequences_per_port[port];
    for (auto kv : sequences) {
        if (timespecToTimestamp(kv.second.t2) <= timestamp) {
            m_sequences_per_port[port].erase(kv.first);
        }
    }
}

bool CTimesyncEngine::isDataValid(CTimesyncPTPData_t *data) {
    return ((data->t1.tv_sec > 0) || (data->t1.tv_nsec > 0)) && ((data->t2.tv_sec > 0) || (data->t2.tv_nsec > 0)) &&
           ((data->t3.tv_sec > 0) || (data->t3.tv_nsec > 0)) && ((data->t4.tv_sec > 0) || (data->t4.tv_nsec > 0));
}

int64_t CTimesyncEngine::evalDelta(int port, uint16_t sequence_id) {
    CTimesyncPTPData_t *data = getData(port, sequence_id);
    if ((data == nullptr) || (!isDataValid(data)))
        return 0;

    int64_t delta = -((int64_t)((timespecToTimestamp(data->t2) - timespecToTimestamp(data->t1)) -
                                (timespecToTimestamp(data->t4) - timespecToTimestamp(data->t3)))) /
                    2;
    setDelta(port, delta);
    cleanupSequencesBefore(port, data->t2);
    return delta;
}

void CTimesyncEngine::setDelta(int port, int64_t delta) {
    auto iter = m_deltas.find(port);
    if (iter != m_deltas.end()) {
        m_deltas[port] = delta;
    } else {
        m_deltas.insert({port, delta});
    }
}

int64_t CTimesyncEngine::getDelta(int port) {
    try {
        return m_deltas.at(port);
    } catch (const std::out_of_range &e) {
        return 0;
    }
}

// Message queue /////////////////////////////////////////////////

bool CTimesyncEngine::isPacketTypeAllowed(TimesyncPacketType type) {
    return (m_is_master && ((type == TimesyncPacketType::PTP_SYNC) || (type == TimesyncPacketType::PTP_FOLLOWUP) ||
                            (type == TimesyncPacketType::PTP_DELAYRESP))) ||
           (!m_is_master && (type == TimesyncPacketType::PTP_DELAYREQ));
}

void CTimesyncEngine::pushNextMessage(int port, uint16_t sequence_id, TimesyncPacketType type, timespec ts) {
    if (!isPacketTypeAllowed(type))
        return;
    CTimesyncPTPPacketQueue_t *packet_queue = getOrCreatePacketQueue(port);
    packet_queue->push({sequence_id, type, ts});
}

CTimesyncPTPPacketData_t CTimesyncEngine::popNextMessage(int port) {
    CTimesyncPTPPacketQueue_t *packet_queue = getPacketQueue(port);
    if (packet_queue == nullptr)
        return {0, TimesyncPacketType::UNKNOWN, {0, 0}};
    CTimesyncPTPPacketData_t next_message = packet_queue->front();
    packet_queue->pop();
    return next_message;
}

bool CTimesyncEngine::hasNextMessage(int port) {
    CTimesyncPTPPacketQueue_t *packet_queue = getPacketQueue(port);
    if (packet_queue == nullptr)
        return false;
    return !(packet_queue->empty());
}

// Helper methods ////////////////////////////////////////////////

CTimesyncSequences_t *CTimesyncEngine::getSequences(int port) {
    auto iter = m_sequences_per_port.find(port);
    if (iter != m_sequences_per_port.end())
        return &m_sequences_per_port[port];
    return nullptr;
}

CTimesyncSequences_t *CTimesyncEngine::getOrCreateSequences(int port) {
    CTimesyncSequences_t sequences;
    try {
        sequences = m_sequences_per_port.at(port);
    } catch (const std::out_of_range &e) {
        sequences = CTimesyncSequences_t();
        m_sequences_per_port.insert({port, sequences});
    }
    return &m_sequences_per_port[port];
}

CTimesyncPTPData_t *CTimesyncEngine::getData(int port, uint16_t sequence_id) {
    CTimesyncSequences_t *sequences = getSequences(port);
    if (sequences == nullptr)
        return nullptr;
    auto iter = sequences->find(sequence_id);
    if (iter != sequences->end())
        return &(*sequences)[sequence_id];
    return nullptr;
}

CTimesyncPTPData_t *CTimesyncEngine::getOrCreateData(int port, uint16_t sequence_id) {
    CTimesyncSequences_t *sequences = getOrCreateSequences(port);
    CTimesyncPTPData_t ptp_data;
    try {
        ptp_data = sequences->at(sequence_id);
    } catch (const std::out_of_range &e) {
        ptp_data = CTimesyncPTPData_t();
        sequences->insert({sequence_id, ptp_data});
    }
    return &(*sequences)[sequence_id];
}

CTimesyncPTPPacketQueue_t *CTimesyncEngine::getPacketQueue(int port) {
    auto iter = m_send_queue_per_port.find(port);
    if (iter != m_send_queue_per_port.end())
        return &m_send_queue_per_port[port];
    return nullptr;
}

CTimesyncPTPPacketQueue_t *CTimesyncEngine::getOrCreatePacketQueue(int port) {
    CTimesyncPTPPacketQueue_t packet_queue;
    try {
        packet_queue = m_send_queue_per_port.at(port);
    } catch (const std::out_of_range &e) {
        packet_queue = CTimesyncPTPPacketQueue_t();
        m_send_queue_per_port.insert({port, packet_queue});
    }
    return &m_send_queue_per_port[port];
}
