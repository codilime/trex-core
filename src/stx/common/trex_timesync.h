#ifndef __TREX_TIMESYNC_H__
#define __TREX_TIMESYNC_H__

#include "stl/trex_stl_fs.h"

#include <common/Network/Packet/EthernetHeader.h>
#include <common/Network/Packet/PTPHeader.h>
#include <common/Network/Packet/PTPPacket.h>

typedef enum TimesyncPacketParser_err {
    TIMESYNC_PARSER_E_OK = 0,
    TIMESYNC_PARSER_E_NO_DATA,
    TIMESYNC_PARSER_E_TOO_SHORT,
    TIMESYNC_PARSER_E_SHORT_PTP_HEADER,
    TIMESYNC_PARSER_E_UNKNOWN_MSG,
    TIMESYNC_PARSER_E_UNKNOWN_HDR,

    // TIMESYNC_PARSER_E_SHORT_IP_HDR,
    // TIMESYNC_PARSER_E_VLAN_NOT_SUP,
    // TIMESYNC_PARSER_E_QINQ_NOT_SUP,
    // TIMESYNC_PARSER_E_MPLS_NOT_SUP,
    // TIMESYNC_PARSER_E_VLAN_NEEDED,
} TimesyncPacketParser_err_t;

/**************************************
 * RXTimesync
 *************************************/
class RXTimesync {
  public:
    RXTimesync(uint8_t timesync_method) { m_timesync_method = timesync_method; };

    void handle_pkt(const rte_mbuf_t *m, int port);

    Json::Value to_json() const;

  private:
    TimesyncPacketParser_err_t parse_ptp_pkt(uint8_t *pkt, uint16_t len);
    void hexdump(const unsigned char *msg, uint16_t len); // TODO remove

  private:
    uint8_t m_timesync_method;

    uint8_t *m_start;
    uint16_t m_len;
    PTPHeader *m_ptp_hdr;
    union {
        PTPPacketSync *m_ptp_packet_sync;
        PTPPacketFollowUp *m_ptp_packet_fwup;
        PTPPacketDelayedReq *m_ptp_packet_dreq;
        PTPPacketDelayedResp *m_ptp_packet_drsp;
    };
    uint8_t m_vlan_offset;
};

#endif
