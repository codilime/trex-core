#include "trex_rx_timesync.h"

#include <trex_global.h>

timespec timestampToTimespec(uint64_t timestamp) {
    return {(uint32_t)(timestamp / (1000 * 1000 * 1000)), (uint32_t)(timestamp % (1000 * 1000 * 1000))};
};

/**************************************
 * RXTimesync
 *************************************/
// RXTimesync::RXTimesync() {}

void RXTimesync::handle_pkt(const rte_mbuf_t *m, int port) {
    if (m_timesync_engine->getTimesyncMethod() == TimesyncMethod::PTP) {
#ifdef _DEBUG
        printf("PTP time synchronisation is currently not supported (but we are working on that).\n");
#endif
        // uint8_t ret = parse_ptp_pkt(rte_pktmbuf_mtod(m, uint8_t *), m->pkt_len);
        parse_ptp_pkt(rte_pktmbuf_mtod(m, uint8_t *), m->pkt_len, port);
    }
}

TimesyncPacketParser_err_t RXTimesync::parse_ptp_pkt(uint8_t *pkt, uint16_t len, int port) {
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
        uint64_t t2 = CGlobalInfo::m_options.get_latency_timestamp();
        // PTP::SyncPacket *sync = reinterpret_cast<PTP::SyncPacket *>(pkt + pkt_offset);
        m_timesync_engine->receivedPTPSync(port, *(header->seq_id), timestampToTimespec(t2));
    } break;
    case PTP::Field::message_type::FOLLOW_UP: {
        PTP::FollowUpPacket *followup = reinterpret_cast<PTP::FollowUpPacket *>(pkt + pkt_offset);
        m_timesync_engine->receivedPTPFollowUp(port, *(header->seq_id), followup->origin_timestamp.get_timestamp());
    } break;
    case PTP::Field::message_type::DELAY_RESP: {
        PTP::DelayedReqPacket *delay_req = reinterpret_cast<PTP::DelayedReqPacket *>(pkt + pkt_offset);
        m_timesync_engine->receivedPTPDelayResp(port, *(header->seq_id), delay_req->origin_timestamp.get_timestamp());
    } break;
    default:
        return TIMESYNC_PARSER_E_UNKNOWN_MSG;
    }
    // TODO

    return TIMESYNC_PARSER_E_OK;
}

void RXTimesync::advertise(int port) {
    // if (m_timesync_engine->getPortState(port) == TimesyncState::INIT)
    //     return;
    // m_timesync_engine->setPortState(port, TimesyncState::INIT);
    // TODO mateusz prepare "PTP" advertisement packet
    // TODO mateusz send the packet using RxPortManager or CRxCore tx_pkt() method
    // m_timesync_engine->sentAdvertisement(port);
}

void RXTimesync::sendPTPDelayReq(int port) {
    // uint64_t timestamp = CGlobalInfo::m_options.get_latency_timestamp();
    // if (m_timesync_engine->getPortState(port) == TimesyncState::WORK)
    //     return;
    // m_timesync_engine->setPortState(port, TimesyncState::WORK);
    // // TODO mateusz prepare PTP delayed request packet
    // // TODO mateusz send the packet using RxPortManager or CRxCore tx_pkt() method
    // m_timesync_engine->sentPTPDelayReq(port, timestamp);
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
