#ifndef __TREX_RX_TIMESYNC_H__
#define __TREX_RX_TIMESYNC_H__

#include "stl/trex_stl_fs.h"

#include <trex_timesync.h>

#include <common/Network/Packet/EthernetHeader.h>
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
    RXTimesync(CTimesyncEngine *engine, int port) {
        m_timesync_engine = engine;
        // m_timesync_engine->setSyncState(TimesyncSlaveSyncState::WAIT);
        m_port = port;
    };

    void handle_pkt(const rte_mbuf_t *m, int port);

    void advertise(int port);

    void sendPTPDelayReq(int port);

    Json::Value to_json() const;

  private:
    TimesyncPacketParser_err_t parse_ptp_pkt(uint8_t *pkt, uint16_t len, int port);
    void hexdump(const unsigned char *msg, uint16_t len); // TODO remove

  private:
    int m_port;
    CTimesyncEngine *m_timesync_engine;
};

#endif
