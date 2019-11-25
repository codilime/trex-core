#include "trex_rx_timesync.h"

#include <trex_global.h>

/**************************************
 * RXTimesync
 *************************************/
// RXTimesync::RXTimesync() {}

void RXTimesync::handle_pkt(const rte_mbuf_t *m, int port) {
    if (m_timesync_method == TimesyncMethod::PTP) {
#ifdef _DEBUG
        printf("PTP time synchronisation is currently not supported (but we are working on that).\n");
#endif
        // uint8_t ret = parse_ptp_pkt(rte_pktmbuf_mtod(m, uint8_t *), m->pkt_len);
        parse_ptp_pkt(m, port);
    }
}

TimesyncPacketParser_err_t RXTimesync::parse_ptp_pkt(const rte_mbuf_t *m, int port) {
    PTP::Header *header;
    uint16_t len = m->pkt_len;
    uint8_t *pkt = rte_pktmbuf_mtod(m, uint8_t *);

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
    hexdump(pkt, len);
    uint16_t pkt_offset = ether_hdr->getSize();
    if (len < pkt_offset + PTP_HDR_LEN)
        return TIMESYNC_PARSER_E_SHORT_PTP_HEADER;

    header = (PTP::Header *)(pkt + pkt_offset);
    header->dump(stdout);

    pkt_offset += PTP_HDR_LEN;

    printf("Hex dump:");
    hexdump(pkt + pkt_offset, len - pkt_offset);

    ptp_data.m = m;
    ptp_data.portid = port;

    switch (header->trn_and_msg.msg_type()) {
    case PTP::Field::message_type::SYNC: {
        PTP::SyncPacket *sync = reinterpret_cast<PTP::SyncPacket *>(pkt + pkt_offset);
        m_timesync_engine->receivedPTPSync(port);
        sync->dump(stdout);
        parse_sync(header, m->timesync);
    } break;
    case PTP::Field::message_type::FOLLOW_UP: {
        PTP::FollowUpPacket *followup = reinterpret_cast<PTP::FollowUpPacket *>(pkt + pkt_offset);
        m_timesync_engine->receivedPTPFollowUp(port, followup->origin_timestamp.get_timestamp());
        followup->dump(stdout);
        parse_fup(header);
    } break;
    case PTP::Field::message_type::DELAY_REQ: {
        PTP::DelayedReqPacket *delay_req = reinterpret_cast<PTP::DelayedReqPacket *>(pkt + pkt_offset);
        m_timesync_engine->receivedPTPDelayReq(port);
        delay_req->dump(stdout);
        parse_delay_req(header);
    } break;
    case PTP::Field::message_type::DELAY_RESP: {
        PTP::DelayedRespPacket *delay_resp = reinterpret_cast<PTP::DelayedRespPacket *>(pkt + pkt_offset);
        m_timesync_engine->receivedPTPDelayResp(port, delay_resp->origin_timestamp.get_timestamp());
        delay_resp->dump(stdout);
        parse_delay_response(header);
    } break;
    default:
        return TIMESYNC_PARSER_E_UNKNOWN_MSG;
    }
    // TODO


    m_timesync_engine->printClockInfo(&ptp_data);

    return TIMESYNC_PARSER_E_OK;
}

void RXTimesync::advertise(int port) {
    if (m_timesync_engine->getPortState(port) == TimesyncState::INIT)
        return;
    m_timesync_engine->setPortState(port, TimesyncState::INIT);
    // TODO mateusz prepare "PTP" advertisement packet
    // TODO mateusz send the packet using RxPortManager or CRxCore tx_pkt() method
    m_timesync_engine->sentAdvertisement(port);
}

void RXTimesync::sendPTPDelayReq(int port) {
    uint64_t timestamp = CGlobalInfo::m_options.get_latency_timestamp();
    if (m_timesync_engine->getPortState(port) == TimesyncState::WORK)
        return;
    m_timesync_engine->setPortState(port, TimesyncState::WORK);
    // TODO mateusz prepare PTP delayed request packet
    // TODO mateusz send the packet using RxPortManager or CRxCore tx_pkt() method
    m_timesync_engine->sentPTPDelayReq(port, timestamp);
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

/*
 * Parse the PTP SYNC message.
 */
void RXTimesync::parse_sync(PTP::Header* header, uint16_t rx_tstamp_idx) {
    ptp_data.seqID_SYNC = header->seq_id.value;

    if (ptp_data.ptpset == 0) {
        rte_memcpy(&ptp_data.master_clock_id,
                &header->source_port_id._clock_id,
                sizeof(struct PTP::clock_id));
        ptp_data.ptpset = 1;
    }

    if (memcmp(&header->source_port_id._clock_id,
            &header->source_port_id._clock_id,
            sizeof(struct PTP::clock_id)) == 0) {

        if (ptp_data.ptpset == 1)
            //TODO add hardware timestamp support
            //rte_eth_timesync_read_rx_timestamp(ptp_data.portid,
            //        &ptp_data.tstamp2, rx_tstamp_idx);
            clock_gettime(CLOCK_REALTIME, &ptp_data.tstamp2);
    }
}

/*
 * Parse the PTP FOLLOWUP message and send DELAY_REQ to the master clock.
 */
void RXTimesync::parse_fup(PTP::Header* header) {
    struct PTP::ptp_message *ptp_msg;
    struct PTP::tstamp *origin_tstamp;
    //int wait_us;
    const struct rte_mbuf *m = ptp_data.m;

    if (memcmp(&ptp_data.master_clock_id,
            &header->source_port_id._clock_id,
            sizeof(struct PTP::clock_id)) != 0)
        return;

    ptp_data.seqID_FOLLOWUP = header->seq_id.value;
    ptp_msg = (struct PTP::ptp_message *) (rte_pktmbuf_mtod(m, char *) +
                      sizeof(struct ether_hdr));

    origin_tstamp = &ptp_msg->follow_up.precise_origin_tstamp;
    ptp_data.tstamp1.tv_nsec = ntohl(origin_tstamp->ns);
    ptp_data.tstamp1.tv_sec =
        ((uint64_t)ntohl(origin_tstamp->sec_lsb)) |
        (((uint64_t)ntohs(origin_tstamp->sec_msb)) << 32);


    if (ptp_data.seqID_FOLLOWUP == ptp_data.seqID_SYNC) {

        //TODO send delay req packet here

        //wait_us = 0;
        ptp_data.tstamp3.tv_nsec = 0;
        ptp_data.tstamp3.tv_sec = 0;

        //TODO add support for hardware timestamping
        /* Wait at least 1 us to read TX timestamp. */ 
        // while ((rte_eth_timesync_read_tx_timestamp(ptp_data.portid,
        //         &ptp_data.tstamp3) < 0) && (wait_us < 1000)) {
        //     rte_delay_us(1);
        //     wait_us++;
        // }
        clock_gettime(CLOCK_REALTIME, &ptp_data.tstamp3);

    }
}

/*
 * Parse the PTP DELAY REQ message and send DELAY_RESPONSE to the client clock.
 */
void RXTimesync::parse_delay_req(PTP::Header* header) {
    //TODO send delay response message
}

/*
 * Parse the DELAY_RESP message.
 */
void RXTimesync::parse_delay_response(PTP::Header* header) {
    const struct rte_mbuf *m = ptp_data.m;
    struct PTP::ptp_message *ptp_msg;
    struct PTP::tstamp *rx_tstamp;
    uint16_t seq_id;

    ptp_msg = (struct PTP::ptp_message *) (rte_pktmbuf_mtod(m, char *) +
                    sizeof(struct ether_hdr));
    seq_id = rte_be_to_cpu_16(ptp_msg->delay_resp.hdr.seq_id);
    //TODO fix clock checks
    // if (memcmp(&ptp_data.client_clock_id,
    //        &ptp_msg->delay_resp.req_port_id.clock_id,
    //        sizeof(struct PTP::clock_id)) == 0) {
        if (seq_id == ptp_data.seqID_FOLLOWUP) {
            rx_tstamp = &ptp_msg->delay_resp.rx_tstamp;
            ptp_data.tstamp4.tv_nsec = ntohl(rx_tstamp->ns);
            ptp_data.tstamp4.tv_sec =
                ((uint64_t)ntohl(rx_tstamp->sec_lsb)) |
                (((uint64_t)ntohs(rx_tstamp->sec_msb)) << 32);

            /* Evaluate the delta for adjustment. */
            ptp_data.delta = m_timesync_engine->delta_eval(&ptp_data);

            //rte_eth_timesync_adjust_time(ptp_data.portid,
            //                 ptp_data.delta);

            ptp_data.current_ptp_port = ptp_data.portid;

        }
   // }
}
