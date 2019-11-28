#include "trex_rx_timesync.h"

#include <trex_global.h>

/**************************************
 * RXTimesync
 *************************************/
// RXTimesync::RXTimesync() {}

void RXTimesync::handle_pkt(const rte_mbuf_t *m, int port) {
    if (m_timesync_engine->getTimesyncMethod() == TimesyncMethod::PTP) {
#ifdef _DEBUG
        printf("PTP time synchronisation is currently not supported (but we are working on that).\n");
#endif
        uint16_t rx_tstamp_idx = 0;

        if (hardware_timestamping_enabled) {
            rx_tstamp_idx = m->timesync;
        }
        // uint8_t ret = parse_ptp_pkt(rte_pktmbuf_mtod(m, uint8_t *), m->pkt_len);
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
    // hexdump(pkt, len);
    uint16_t pkt_offset = ether_hdr->getSize();
    if (len < pkt_offset + PTP_HDR_LEN)
        return TIMESYNC_PARSER_E_SHORT_PTP_HEADER;

    header = (PTP::Header *)(pkt + pkt_offset);
    // header->dump(stdout);

    pkt_offset += PTP_HDR_LEN;

    // printf("Hex dump:");
    // hexdump(pkt + pkt_offset, len - pkt_offset);

    switch (header->trn_and_msg.msg_type()) {
    case PTP::Field::message_type::SYNC: {
        PTP::SyncPacket *sync = reinterpret_cast<PTP::SyncPacket *>(pkt + pkt_offset);
        timespec t;
        parse_sync(rx_tstamp_idx, &t, port);
        m_timesync_engine->receivedPTPSync(port, header->seq_id.value, t);
        sync->dump(stdout);     
    } break;
    case PTP::Field::message_type::FOLLOW_UP: {
        PTP::FollowUpPacket *followup = reinterpret_cast<PTP::FollowUpPacket *>(pkt + pkt_offset);
        timespec t;
        parse_fup(followup, &t);
        m_timesync_engine->receivedPTPFollowUp(port, header->seq_id.value, t);
        //TODO fix dump 
        //followup->dump(stdout);
    } break;
    case PTP::Field::message_type::DELAY_REQ: {
        PTP::DelayedReqPacket *delay_req = reinterpret_cast<PTP::DelayedReqPacket *>(pkt + pkt_offset);
        timespec t;
        parse_delay_request(rx_tstamp_idx, &t, port);
        m_timesync_engine->receivedPTPDelayReq(port, header->seq_id.value, t);
        delay_req->dump(stdout);
    } break;
    case PTP::Field::message_type::DELAY_RESP: {
        PTP::DelayedRespPacket *delay_resp = reinterpret_cast<PTP::DelayedRespPacket *>(pkt + pkt_offset);
        timespec t;
        parse_delay_response(delay_resp, &t);
        m_timesync_engine->receivedPTPDelayResp(port, header->seq_id.value, t);
        delay_resp->dump(stdout);
    } break;
    default:
        return TIMESYNC_PARSER_E_UNKNOWN_MSG;
    }
    // TODO

    return TIMESYNC_PARSER_E_OK;
}

void RXTimesync::hexdump(const unsigned char *msg, uint16_t len) {
    // https://stackoverflow.com/questions/7775991/how-to-get-hexdump-of-a-structure-data
    int i;
    unsigned char buff[17];
    for (i = 0; i < len; i++) {
        if ((i % 16) == 0) {
            if (i != 0)
                printf("  %s\n", buff);
            printf("  %04x ", i);
        }
        printf(" %02x", msg[i]);
        if ((msg[i] < 0x20) || (msg[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = msg[i];
        buff[(i % 16) + 1] = '\0';
    }
    while ((i % 16) != 0) {
        printf("   ");
        i++;
    }
    printf("  %s\n", buff);
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
