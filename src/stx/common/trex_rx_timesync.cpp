#include "trex_rx_timesync.h"

#include <trex_global.h>

/**************************************
 * RXTimesync
 *************************************/

void RXTimesync::handle_pkt(rte_mbuf_t *m, int port) {
    if (m_timesync_engine->getTimesyncMethod() == TimesyncMethod::PTP) {
        uint16_t rx_tstamp_idx = 0;
        m_mbuf = m;

        if (hardware_timestamping_enabled) {
            rx_tstamp_idx = m->timesync;
        }

        if (m->pkt_len < ETH_HDR_LEN)
            return;

        uint64_t m_timestamp = 0;
        if (CGlobalInfo::m_options.is_timesync_rx_callback_enabled()) {
            m_timestamp = m->timestamp;
        }
        uint8_t *pkt = rte_pktmbuf_mtod(m, uint8_t *);
        EthernetHeader *ether_hdr = (EthernetHeader *)pkt;
        uint32_t offset = ether_hdr->getSize();
        switch (ether_hdr->getNextProtocol()) {
        case EthernetHeader::Protocol::IP:
            parse_ip_pkt(pkt + offset, m->pkt_len - offset, rx_tstamp_idx, port, m_timestamp);
            break;
        case EthernetHeader::Protocol::PTP:
            // TODO what about vxlan support (a.k.a. CFlowStatParser.m_flags |= FSTAT_PARSER_VXLAN_SKIP)
            parse_ptp_pkt(pkt + offset, m->pkt_len - offset, rx_tstamp_idx, port, m_timestamp);
            break;
        }
    }
}

TimesyncPacketParser_err_t RXTimesync::parse_ip_pkt(uint8_t *pkt, uint16_t len, uint16_t rx_tstamp_idx, int port, uint64_t m_timestamp) {
    if (pkt == NULL)
        return TIMESYNC_PARSER_E_NO_DATA;
    if (len < IPV4_HDR_LEN + UDP_HEADER_LEN)
        return TIMESYNC_PARSER_E_TOO_SHORT;

    IPHeader *ip_hdr = (IPHeader *)pkt;
    switch (ip_hdr->getNextProtocol()) {
        case IPHeader::Protocol::UDP:
            return parse_ptp_pkt(pkt + IPV4_HDR_LEN + UDP_HEADER_LEN, len - IPV4_HDR_LEN - UDP_HEADER_LEN, rx_tstamp_idx, port, m_timestamp);
        default:
            return TIMESYNC_PARSER_E_UNKNOWN_HDR;
    }
}

TimesyncPacketParser_err_t RXTimesync::parse_ptp_pkt(uint8_t *pkt, uint16_t len, uint16_t rx_tstamp_idx, int port, uint64_t m_timestamp) {
    if (pkt == NULL)
        return TIMESYNC_PARSER_E_NO_DATA;
    if (len < PTP_HDR_LEN)
        return TIMESYNC_PARSER_E_SHORT_PTP_HEADER;

    int i;
    PTP::Header *header = (PTP::Header *)pkt;
    switch (header->trn_and_msg.msg_type()) {
    case PTP::Field::message_type::SYNC: {
        // PTP::SyncPacket *sync = reinterpret_cast<PTP::SyncPacket *>(pkt + PTP_HDR_LEN);
        timespec t;
        i = parse_sync(rx_tstamp_idx, &t, port, m_timestamp);
        // try fe
        if (i != 0) {
            return TIMESYNC_PARSER_E_NO_TIMESTAMP;
        }
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
        i = parse_delay_request(rx_tstamp_idx, &t, port, m_timestamp);
        if (i != 0) {
            return TIMESYNC_PARSER_E_NO_TIMESTAMP;
        }
        m_timesync_engine->receivedPTPDelayReq(port, *(header->seq_id), t, header->source_port_id);
    } break;
    case PTP::Field::message_type::DELAY_RESP: {
        PTP::DelayedRespPacket *delay_resp = reinterpret_cast<PTP::DelayedRespPacket *>(pkt + PTP_HDR_LEN);
        timespec t;
        parse_delay_response(delay_resp, &t);
        m_timesync_engine->receivedPTPDelayResp(port, *(header->seq_id), t, header->source_port_id,
                                                delay_resp->req_clock_identity);
        if (hardware_timestamping_enabled && m_timesync_engine->isDeltaValid(port)) {
            int64_t delta = m_timesync_engine->getDelta(port);
            if (delta != 0) {
                int i = rte_eth_timesync_adjust_time(port, delta);
                if (i < 0) {
                    printf("Error (%d) adjusting hardware clock on port %d.  Falling back to latency offsetting.\n", i, port);
                    break;
                }
            }
            m_timesync_engine->setHardwareClockAdjusted(port, true);
        }
    } break;
    default:
        return TIMESYNC_PARSER_E_UNKNOWN_MSG;
    }

    return TIMESYNC_PARSER_E_OK;
}

Json::Value RXTimesync::to_json() const { return Json::objectValue; }

int RXTimesync::parse_sync(uint16_t rx_tstamp_idx, timespec *t, int port, uint64_t m_timestamp) {
    int i;
    if (! (m_mbuf->ol_flags & PKT_RX_IEEE1588_TMST)) {
        printf("Received PTP Sync packet not timestamped by hardware\n");
    }

    if (hardware_timestamping_enabled) {
        printf("Reading time from hardware\n");
        i = rte_eth_timesync_read_rx_timestamp(port,
            t, rx_tstamp_idx);
        if (i != 0) {
            *t = timestampToTimespec(m_timestamp);
            i = m_timestamp > 0 ? 0 : -1;
        }
    } else if (CGlobalInfo::m_options.is_timesync_rx_callback_enabled()) {
        *t = timestampToTimespec(m_timestamp);
        i = m_timestamp > 0 ? 0 : -1;
    } else {
        i = clock_gettime(CLOCK_REALTIME, t);
    }
    if (i != 0) {
        printf("Error in PTP synchronization - failed to read rx SYNC timestamp, error code: %i\n", i);
    }
    return i;
}

void RXTimesync::parse_fup(PTP::FollowUpPacket *followup, timespec *t) {
    *t = followup->origin_timestamp.get_timestamp();
}

int RXTimesync::parse_delay_request(uint16_t rx_tstamp_idx, timespec *t, int port, uint64_t m_timestamp) {
    int i;

    if (! (m_mbuf->ol_flags & PKT_RX_IEEE1588_TMST)) {
        printf("Received PTP delay_request packet not timestamped by hardware\n");
    }

    if (hardware_timestamping_enabled) {
        i = rte_eth_timesync_read_rx_timestamp(port,
            t, rx_tstamp_idx);
        if (i != 0) {
            *t = timestampToTimespec(m_timestamp);
            i = m_timestamp > 0 ? 0 : -1;
        }
    } else if (CGlobalInfo::m_options.is_timesync_rx_callback_enabled()) {
        *t = timestampToTimespec(m_timestamp);
        i = m_timestamp > 0 ? 0 : -1;
    } else {
        i = clock_gettime(CLOCK_REALTIME, t);
    }
    if (i != 0) {
        printf("Error in PTP synchronization - failed to read rx DELAY_REQ timestamp, error code: %i\n", i);
    }
    return i;
}

void RXTimesync::parse_delay_response(PTP::DelayedRespPacket *delay_resp, timespec *t) {
    *t = delay_resp->origin_timestamp.get_timestamp();
}
