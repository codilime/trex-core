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

        if (m->pkt_len < ETH_HDR_LEN)
            return;

        uint8_t *pkt = rte_pktmbuf_mtod(m, uint8_t *);
        EthernetHeader *ether_hdr = (EthernetHeader *)pkt;
        uint32_t offset = ether_hdr->getSize();
        switch (ether_hdr->getNextProtocol()) {
        case EthernetHeader::Protocol::IP:
            parse_ip_pkt(pkt + offset, m->pkt_len - offset, rx_tstamp_idx, port);
            break;
        case EthernetHeader::Protocol::PTP:
            // TODO what about vxlan support (a.k.a. CFlowStatParser.m_flags |= FSTAT_PARSER_VXLAN_SKIP)
            parse_ptp_pkt(pkt + offset, m->pkt_len - offset, rx_tstamp_idx, port);
            break;
        }
    }
}

TimesyncPacketParser_err_t RXTimesync::parse_ip_pkt(uint8_t *pkt, uint16_t len, uint16_t rx_tstamp_idx, int port) {
    if (pkt == NULL)
        return TIMESYNC_PARSER_E_NO_DATA;
    if (len < IPV4_HDR_LEN + UDP_HEADER_LEN)
        return TIMESYNC_PARSER_E_TOO_SHORT;

    IPHeader *ip_hdr = (IPHeader *)pkt;
    switch (ip_hdr->getNextProtocol()) {
        case IPHeader::Protocol::UDP:
            return parse_ptp_pkt(pkt + IPV4_HDR_LEN + UDP_HEADER_LEN, len - IPV4_HDR_LEN - UDP_HEADER_LEN, rx_tstamp_idx, port);
        default:
            return TIMESYNC_PARSER_E_UNKNOWN_HDR;
    }
}

TimesyncPacketParser_err_t RXTimesync::parse_ptp_pkt(uint8_t *pkt, uint16_t len, uint16_t rx_tstamp_idx, int port) {
    if (pkt == NULL)
        return TIMESYNC_PARSER_E_NO_DATA;
    if (len < PTP_HDR_LEN)
        return TIMESYNC_PARSER_E_SHORT_PTP_HEADER;

    PTP::Header *header = (PTP::Header *)pkt;
    switch (header->trn_and_msg.msg_type()) {
    case PTP::Field::message_type::SYNC: {
        // PTP::SyncPacket *sync = reinterpret_cast<PTP::SyncPacket *>(pkt + PTP_HDR_LEN);
        timespec t;
        parse_sync(rx_tstamp_idx, &t, port);
        m_timesync_engine->receivedPTPSync(port, *(header->seq_id), t, header->source_port_id);
    } break;
    case PTP::Field::message_type::FOLLOW_UP: {
        PTP::FollowUpPacket *followup = reinterpret_cast<PTP::FollowUpPacket *>(pkt + PTP_HDR_LEN);
        timespec t;
        parse_fup(followup, &t);
        m_timesync_engine->receivedPTPFollowUp(port, *(header->seq_id), t, header->source_port_id);
    } break;
    case PTP::Field::message_type::PDELAY_REQ: {
        // PTP::DelayedReqPacket *delay_req = reinterpret_cast<PTP::DelayedReqPacket *>(pkt + PTP_HDR_LEN);
        timespec t;
        parse_delay_request(rx_tstamp_idx, &t, port);
        m_timesync_engine->receivedPTPDelayReq(port, *(header->seq_id), t, header->source_port_id);
    } break;
    case PTP::Field::message_type::DELAY_RESP: {
        PTP::DelayedRespPacket *delay_resp = reinterpret_cast<PTP::DelayedRespPacket *>(pkt + PTP_HDR_LEN);
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
    int i;
    if (hardware_timestamping_enabled) {
        i = rte_eth_timesync_read_rx_timestamp(port,
            t, rx_tstamp_idx); 
    } else {
        i = clock_gettime(CLOCK_REALTIME, t);
    }
    if (i != 0) {
        printf("Error in PTP synchronization - failed to read tx timestamp, error code: %i\n", i);
        return;
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
