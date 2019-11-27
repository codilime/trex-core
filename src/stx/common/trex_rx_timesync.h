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
} TimesyncPacketParser_err_t;

/**************************************
 * RXTimesync
 *************************************/
class RXTimesync {
  public:
    RXTimesync(CTimesyncEngine *engine, int port) {
        m_timesync_engine = engine;
        m_port = port;
        TrexPlatformApi &api = get_platform_api();
        hardware_timestamping_enabled = api.getPortAttrObj(port)->is_hardware_timesync_enabled();
    };

    void handle_pkt(const rte_mbuf_t *m, int port);

    void advertise(int port);

    void sendPTPDelayReq(int port);

    Json::Value to_json() const;

    bool hardware_timestamping_enabled;

  private:
    TimesyncPacketParser_err_t parse_ptp_pkt(uint8_t *pkt, uint16_t len, uint16_t rx_tstamp_idx, int port);
    void hexdump(const unsigned char *msg, uint16_t len); // TODO remove
    void parse_sync(uint16_t rx_tstamp_idx, timespec *t, int port);
    void parse_fup(PTP::FollowUpPacket *followup, timespec *t);
    void parse_delay_request(uint16_t rx_tstamp_idx, timespec *t, int port);
    void parse_delay_response(PTP::DelayedRespPacket *delay_resp, timespec *t);

  private:
    int m_port;
    CTimesyncEngine *m_timesync_engine;
};

#endif
