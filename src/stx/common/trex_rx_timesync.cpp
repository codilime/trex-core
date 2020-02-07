#include "trex_rx_timesync.h"

#include <trex_global.h>

/**************************************
 * RXTimesync
 *************************************/

void RXTimesync::handle_pkt(const rte_mbuf_t *m, int port) {
    if (m_timesync_engine->getTimesyncMethod() == TimesyncMethod::PTP) {

        timespec t { 0, 0 };

        if (m->pkt_len < ETH_HDR_LEN)
            return;

        if (hardware_timestamping_enabled && (m->ol_flags & PKT_RX_IEEE1588_TMST)) {
            if (rte_eth_timesync_read_rx_timestamp(port, &t, m->timesync) != 0) {
                printf("Cannot read hardware timestamp from hardware");
            }
        } else if (CGlobalInfo::m_options.is_timesync_rx_callback_enabled()) {
            t = timestampToTimespec(m->timestamp);
        } else {
            if (clock_gettime(CLOCK_REALTIME, &t) != 0) {
                printf("Something is wrong!!! Cannot read time from kernel!");
            }
        }

        uint8_t *pkt = rte_pktmbuf_mtod(m, uint8_t *);
        EthernetHeader *ether_hdr = (EthernetHeader *)pkt;
        uint32_t offset = ether_hdr->getSize();
        switch (ether_hdr->getNextProtocol()) {
        case EthernetHeader::Protocol::IP:
            parse_ip_pkt(pkt + offset, m->pkt_len - offset, &t, port);
            break;
        case EthernetHeader::Protocol::PTP:
            // TODO what about vxlan support (a.k.a. CFlowStatParser.m_flags |= FSTAT_PARSER_VXLAN_SKIP)
            parse_ptp_pkt(pkt + offset, m->pkt_len - offset, &t, port);
            break;
        }
    }
}

TimesyncPacketParser_err_t RXTimesync::parse_ip_pkt(uint8_t *pkt, uint16_t len, timespec* t, int port) {
    if (pkt == NULL)
        return TIMESYNC_PARSER_E_NO_DATA;

    if (len < IPV4_HDR_LEN + UDP_HEADER_LEN)
        return TIMESYNC_PARSER_E_TOO_SHORT;

    IPHeader *ip_hdr = (IPHeader *)pkt;
    switch (ip_hdr->getNextProtocol()) {
        case IPHeader::Protocol::UDP:
            return parse_ptp_pkt(pkt + IPV4_HDR_LEN + UDP_HEADER_LEN, len - IPV4_HDR_LEN - UDP_HEADER_LEN, t, port);
        default:
            return TIMESYNC_PARSER_E_UNKNOWN_HDR;
    }
}

TimesyncPacketParser_err_t RXTimesync::parse_ptp_pkt(uint8_t *pkt, uint16_t len, timespec* t, int port) {
    if (pkt == NULL)
        return TIMESYNC_PARSER_E_NO_DATA;
    if (len < PTP_HDR_LEN)
        return TIMESYNC_PARSER_E_SHORT_PTP_HEADER;

    PTP::Header *header = (PTP::Header *)pkt;
    switch (header->trn_and_msg.msg_type()) {

    case PTP::Field::message_type::SYNC: {
        if (t->tv_sec == 0 && t->tv_nsec == 0)
            return TIMESYNC_PARSER_E_NO_TIMESTAMP;

        m_timesync_engine->receivedPTPSync(port, *(header->seq_id), *t, header->source_port_id);
    } break;

    case PTP::Field::message_type::FOLLOW_UP: {
        PTP::FollowUpPacket *followup = reinterpret_cast<PTP::FollowUpPacket *>(pkt + PTP_HDR_LEN);
        *t = followup->origin_timestamp.get_timestamp();

        m_timesync_engine->receivedPTPFollowUp(port, *(header->seq_id), *t, header->source_port_id);
    } break;

    case PTP::Field::message_type::PDELAY_REQ: {
        if (t->tv_sec == 0 && t->tv_nsec == 0)
            return TIMESYNC_PARSER_E_NO_TIMESTAMP;

        m_timesync_engine->receivedPTPDelayReq(port, *(header->seq_id), *t, header->source_port_id);
    } break;

    case PTP::Field::message_type::DELAY_RESP: {
        PTP::DelayedRespPacket *delay_resp = reinterpret_cast<PTP::DelayedRespPacket *>(pkt + PTP_HDR_LEN);
        *t = delay_resp->origin_timestamp.get_timestamp();

        m_timesync_engine->receivedPTPDelayResp(port, *(header->seq_id), *t, header->source_port_id,
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