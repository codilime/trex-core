#include "trex_rx_timesync.h"

#include <trex_global.h>

/**************************************
 * RXTimesync
 *************************************/

void RXTimesync::handle_pkt(const rte_mbuf_t *m, int port) {
    if (m_timesync_engine->getTimesyncMethod() == TimesyncMethod::PTP) {
        uint16_t rx_tstamp_idx = 0;

        if (hardware_timestamping_enabled) {
            rx_tstamp_idx = m->timesync;
        }
        parse_ptp_pkt(rte_pktmbuf_mtod(m, uint8_t *), m->pkt_len, rx_tstamp_idx, port);
    }
}

TimesyncPacketParser_err_t RXTimesync::parse_ptp_pkt(uint8_t *pkt, uint16_t len, uint16_t rx_tstamp_idx, int port) {
    PTP::Header *header;

    if (pkt == NULL) {
        return TIMESYNC_PARSER_E_NO_DATA;
    }

    // TODO what about vxlan support (a.k.a. CFlowStatParser.m_flags |= FSTAT_PARSER_VXLAN_SKIP)

    if (len < ETH_HDR_LEN)
        return TIMESYNC_PARSER_E_TOO_SHORT;

    EthernetHeader *ether_hdr = (EthernetHeader *)pkt;
    uint16_t next_hdr = ether_hdr->getNextProtocol();

    if (next_hdr != EthernetHeader::Protocol::PTP) {
        return TIMESYNC_PARSER_E_UNKNOWN_HDR;
    }

    uint16_t pkt_offset = ether_hdr->getSize();
    if (len < pkt_offset + PTP_HDR_LEN)
        return TIMESYNC_PARSER_E_SHORT_PTP_HEADER;

    header = (PTP::Header *)(pkt + pkt_offset);

    pkt_offset += PTP_HDR_LEN;

    switch (header->trn_and_msg.msg_type()) {
    case PTP::Field::message_type::SYNC: {
        // PTP::SyncPacket *sync = reinterpret_cast<PTP::SyncPacket *>(pkt + pkt_offset);
        timespec t;
        parse_sync(rx_tstamp_idx, &t, port);
        m_timesync_engine->receivedPTPSync(port, *(header->seq_id), t, header->source_port_id);
    } break;
    case PTP::Field::message_type::FOLLOW_UP: {
        PTP::FollowUpPacket *followup = reinterpret_cast<PTP::FollowUpPacket *>(pkt + pkt_offset);
        timespec t;
        parse_fup(followup, &t);
        m_timesync_engine->receivedPTPFollowUp(port, *(header->seq_id), t, header->source_port_id);
    } break;
    case PTP::Field::message_type::DELAY_REQ: {
        // PTP::DelayedReqPacket *delay_req = reinterpret_cast<PTP::DelayedReqPacket *>(pkt + pkt_offset);
        timespec t;
        parse_delay_request(rx_tstamp_idx, &t, port);
        m_timesync_engine->receivedPTPDelayReq(port, *(header->seq_id), t, header->source_port_id);
    } break;
    case PTP::Field::message_type::DELAY_RESP: {
        PTP::DelayedRespPacket *delay_resp = reinterpret_cast<PTP::DelayedRespPacket *>(pkt + pkt_offset);
        timespec t;
        parse_delay_response(delay_resp, &t);
        m_timesync_engine->receivedPTPDelayResp(port, *(header->seq_id), t, header->source_port_id,
                                                delay_resp->req_clock_identity);
    } break;
    default:
        return TIMESYNC_PARSER_E_UNKNOWN_MSG;
    }

    return TIMESYNC_PARSER_E_OK;
}

Json::Value RXTimesync::to_json() const { return Json::objectValue; }

void RXTimesync::parse_sync(uint16_t rx_tstamp_idx, timespec *t, int port) {
    if (hardware_timestamping_enabled) {
        rte_eth_timesync_read_rx_timestamp(port,
            t, rx_tstamp_idx); 
    } else {
        clock_gettime(CLOCK_REALTIME, t);
    }
}

void RXTimesync::parse_fup(PTP::FollowUpPacket *followup, timespec *t) {
    *t = followup->origin_timestamp.get_timestamp();
}

void RXTimesync::parse_delay_request(uint16_t rx_tstamp_idx, timespec *t, int port) {
    if (hardware_timestamping_enabled) {
        rte_eth_timesync_read_rx_timestamp(port,
            t, rx_tstamp_idx);
    } else {
        clock_gettime(CLOCK_REALTIME, t);
    }
}

void RXTimesync::parse_delay_response(PTP::DelayedRespPacket *delay_resp, timespec *t) {
    *t = delay_resp->origin_timestamp.get_timestamp();
}
