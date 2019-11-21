#include "trex_rx_timesync.h"

#include "trex_global.h"

/**************************************
 * RXTimesync
 *************************************/
// RXTimesync::RXTimesync() {}

void RXTimesync::handle_pkt(const rte_mbuf_t *m, int port) {
    if (m_timesync_method == TimesyncMethod::PTP) {
        printf("Syncing time with PTP method (slave side)\tengine=%p.\n", m_timesync_engine);
#ifdef _DEBUG
        printf("PTP time synchronisation is currently not supported (but we are working on that).\n");
#endif
        // uint8_t ret = parse_ptp_pkt(rte_pktmbuf_mtod(m, uint8_t *), m->pkt_len);
        parse_ptp_pkt(rte_pktmbuf_mtod(m, uint8_t *), m->pkt_len, port);
    }
}

TimesyncPacketParser_err_t RXTimesync::parse_ptp_pkt(uint8_t *pkt, uint16_t len, int port) {
    PTP::Header* header;

    if (pkt == NULL) {
        return TIMESYNC_PARSER_E_NO_DATA;
    }
    hexdump(pkt, len);

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
    header->dump(stdout);

    pkt_offset += PTP_HDR_LEN;

    printf("Hex dump:");
    hexdump(pkt + pkt_offset, len - pkt_offset);

    switch (header->trn_and_msg.msg_type()) {
    case PTP::Field::message_type::SYNC:{
        PTP::SyncPacket* sync = reinterpret_cast<PTP::SyncPacket *>(pkt + pkt_offset);
        m_timesync_engine->receivedPTPSync(port);
        sync->dump(stdout);
    }break;
    case PTP::Field::message_type::FOLLOW_UP:{
        PTP::FollowUpPacket* followup = reinterpret_cast<PTP::FollowUpPacket *>(pkt + pkt_offset);
        m_timesync_engine->receivedPTPFollowUp(port, followup->origin_timestamp.get_timestamp());
        followup->dump(stdout);
    }break;
    case PTP::Field::message_type::DELAY_REQ:{
        PTP::DelayedReqPacket* delay_req = reinterpret_cast<PTP::DelayedReqPacket *>(pkt + pkt_offset);
        m_timesync_engine->receivedPTPDelayReq(port);
        delay_req->dump(stdout);
    }break;
    case PTP::Field::message_type::DELAY_RESP:{
        PTP::DelayedRespPacket* delay_resp = reinterpret_cast<PTP::DelayedRespPacket *>(pkt + pkt_offset);
        m_timesync_engine->receivedPTPDelayResp(port, delay_resp->origin_timestamp.get_timestamp());
        delay_resp->dump(stdout);
    }break;
    default:
        return TIMESYNC_PARSER_E_UNKNOWN_MSG;
    }
    // TODO

    return TIMESYNC_PARSER_E_OK;
}

void RXTimesync::advertize(int port) {
    // TODO send an advertisement to future PTP Master (TRex RX)
    m_timesync_engine->sentAdvertisement(port);
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
