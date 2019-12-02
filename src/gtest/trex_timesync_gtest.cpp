/*
 Mateusz Neumann
 Codilime Sp. z o.o.
*/

/*
Copyright (c) 2019 Codilime Sp. z o.o.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <common/gtest.h>

#include "bp_gtest.h"

#include "trex_timesync.h"
#include "trex_rx_timesync.h"
#include "../stx/stl/trex_stl_stream_node.h"

#define MAX_SEC 2147483647
#define PORT_ID 0
#define SEQUENCE_ID 1
#define CLOCK_ID_M1 {0x01, 0}
#define CLOCK_ID_M2 {0x02, 0}
#define CLOCK_ID_S1 {0x11, 0}
#define CLOCK_ID_S2 {0x12, 0}

class timesync_engine_test : public trexStlTest {
  protected:
    virtual void SetUp() {}
    virtual void TearDown() {}

  public:
};

TEST_F(timesync_engine_test, slave_setup) {
    CTimesyncEngine engine;
    engine.setTimesyncMethod(TimesyncMethod::PTP);
    EXPECT_EQ((int)TimesyncMethod::PTP, (int)engine.getTimesyncMethod());
    engine.setTimesyncMaster(false);
    EXPECT_EQ(false, engine.isTimesyncMaster());
}

TEST_F(timesync_engine_test, slave_delta_positive) {
    CTimesyncEngine engine;
    engine.setTimesyncMethod(TimesyncMethod::PTP);
    engine.setTimesyncMaster(false);
    engine.receivedPTPSync(PORT_ID, SEQUENCE_ID, {1, 0}, {});
    engine.receivedPTPFollowUp(PORT_ID, SEQUENCE_ID, {0, 500 * 1000 * 1000}, {});
    engine.sentPTPDelayReq(PORT_ID, SEQUENCE_ID, {2, 0}, {});
    engine.receivedPTPDelayResp(PORT_ID, SEQUENCE_ID, {3, 0}, {}, {});
    EXPECT_EQ(250 * 1000 * 1000, engine.getDelta(PORT_ID));
}

TEST_F(timesync_engine_test, slave_delta_zero_large) {
    CTimesyncEngine engine;
    engine.setTimesyncMethod(TimesyncMethod::PTP);
    engine.setTimesyncMaster(false);
    engine.receivedPTPSync(PORT_ID, SEQUENCE_ID, {MAX_SEC - 2, 100 * 1000 * 1000}, {});
    engine.receivedPTPFollowUp(PORT_ID, SEQUENCE_ID, {MAX_SEC - 3, 0}, {});
    engine.sentPTPDelayReq(PORT_ID, SEQUENCE_ID, {MAX_SEC - 1, 300 * 1000 * 1000}, {});
    engine.receivedPTPDelayResp(PORT_ID, SEQUENCE_ID, {MAX_SEC, 100 * 1000 * 1000}, {}, {});
    EXPECT_EQ(-150 * 1000 * 1000, engine.getDelta(PORT_ID));
}

TEST_F(timesync_engine_test, slave_delta_invalid_setup) {
    CTimesyncEngine engine;
    engine.setTimesyncMethod(TimesyncMethod::PTP);
    engine.setTimesyncMaster(true);
    engine.receivedPTPSync(PORT_ID, SEQUENCE_ID, {MAX_SEC - 2, 100 * 1000 * 1000}, {});
    engine.receivedPTPFollowUp(PORT_ID, SEQUENCE_ID, {MAX_SEC - 3, 0}, {});
    engine.sentPTPDelayReq(PORT_ID, SEQUENCE_ID, {MAX_SEC - 1, 300 * 1000 * 1000}, {});
    engine.receivedPTPDelayResp(PORT_ID, SEQUENCE_ID, {MAX_SEC, 100 * 1000 * 1000}, {}, {});
    EXPECT_EQ(0, engine.getDelta(PORT_ID));
}

TEST_F(timesync_engine_test, slave_delta_invalid_delayreq_sequence_id) {
    CTimesyncEngine engine;
    engine.setTimesyncMethod(TimesyncMethod::PTP);
    engine.setTimesyncMaster(false);
    engine.receivedPTPSync(PORT_ID, SEQUENCE_ID, {1, 0}, {});
    engine.receivedPTPFollowUp(PORT_ID, SEQUENCE_ID, {0, 0}, {});
    engine.sentPTPDelayReq(PORT_ID, SEQUENCE_ID + 1, {2, 0}, {});
    engine.receivedPTPDelayResp(PORT_ID, SEQUENCE_ID, {4, 0}, {}, {});
    EXPECT_EQ(0, engine.getDelta(PORT_ID));
}

TEST_F(timesync_engine_test, slave_delta_mixed_processes) {
    CTimesyncEngine engine;
    engine.setTimesyncMethod(TimesyncMethod::PTP);
    engine.setTimesyncMaster(false);
    engine.receivedPTPSync(PORT_ID, SEQUENCE_ID + 1, {5, 0}, {});
    engine.receivedPTPSync(PORT_ID, SEQUENCE_ID, {2, 0}, {});
    engine.receivedPTPFollowUp(PORT_ID, SEQUENCE_ID, {1, 0}, {});
    engine.receivedPTPFollowUp(PORT_ID, SEQUENCE_ID + 1, {3, 0}, {});
    engine.sentPTPDelayReq(PORT_ID, SEQUENCE_ID, {3, 0}, {});
    engine.receivedPTPDelayResp(PORT_ID, SEQUENCE_ID, {5, 0}, {}, {});
    engine.sentPTPDelayReq(PORT_ID, SEQUENCE_ID + 1, {6, 0}, {});
    EXPECT_EQ(500 * 1000 * 1000, engine.getDelta(PORT_ID));
    engine.receivedPTPDelayResp(PORT_ID, SEQUENCE_ID + 1, {7, 0}, {}, {});
    EXPECT_EQ(-500 * 1000 * 1000, engine.getDelta(PORT_ID));
}

TEST_F(timesync_engine_test, slave_delta_skip_deprecated_process) {
    CTimesyncEngine engine;
    engine.setTimesyncMethod(TimesyncMethod::PTP);
    engine.setTimesyncMaster(false);
    engine.receivedPTPSync(PORT_ID, SEQUENCE_ID, {2, 0}, {});
    engine.receivedPTPFollowUp(PORT_ID, SEQUENCE_ID, {1, 0}, {});
    engine.sentPTPDelayReq(PORT_ID, SEQUENCE_ID, {3, 0}, {});
    engine.receivedPTPSync(PORT_ID, SEQUENCE_ID + 1, {5, 0}, {});
    engine.receivedPTPFollowUp(PORT_ID, SEQUENCE_ID + 1, {3, 0}, {});
    engine.sentPTPDelayReq(PORT_ID, SEQUENCE_ID + 1, {6, 0}, {});
    engine.receivedPTPDelayResp(PORT_ID, SEQUENCE_ID + 1, {7, 0}, {}, {});
    EXPECT_EQ(-500 * 1000 * 1000, engine.getDelta(PORT_ID));
    engine.receivedPTPDelayResp(PORT_ID, SEQUENCE_ID, {5, 0}, {}, {});
    EXPECT_EQ(-500 * 1000 * 1000, engine.getDelta(PORT_ID));
}

TEST_F(timesync_engine_test, slave_delta_valid_src_port_id) {
    CTimesyncEngine engine;
    engine.setTimesyncMethod(TimesyncMethod::PTP);
    engine.setTimesyncMaster(false);
    engine.receivedPTPSync(PORT_ID, SEQUENCE_ID, {2, 0}, CLOCK_ID_M1);
    engine.receivedPTPFollowUp(PORT_ID, SEQUENCE_ID, {1, 0}, CLOCK_ID_M1);
    engine.sentPTPDelayReq(PORT_ID, SEQUENCE_ID, {3, 0}, CLOCK_ID_S1);
    engine.receivedPTPDelayResp(PORT_ID, SEQUENCE_ID, {5, 0}, CLOCK_ID_M1, CLOCK_ID_S1);
    EXPECT_EQ(500 * 1000 * 1000, engine.getDelta(PORT_ID));
}

TEST_F(timesync_engine_test, slave_delta_invalid_src_port_id_1) {
    CTimesyncEngine engine;
    engine.setTimesyncMethod(TimesyncMethod::PTP);
    engine.setTimesyncMaster(false);
    engine.receivedPTPSync(PORT_ID, SEQUENCE_ID, {2, 0}, CLOCK_ID_M1);
    engine.receivedPTPFollowUp(PORT_ID, SEQUENCE_ID, {1, 0}, CLOCK_ID_M2);
    engine.sentPTPDelayReq(PORT_ID, SEQUENCE_ID, {3, 0}, CLOCK_ID_S1);
    engine.receivedPTPDelayResp(PORT_ID, SEQUENCE_ID, {5, 0}, CLOCK_ID_M1, CLOCK_ID_S1);
    EXPECT_EQ(0 * 1000 * 1000, engine.getDelta(PORT_ID));
}

TEST_F(timesync_engine_test, slave_delta_invalid_src_port_id_2) {
    CTimesyncEngine engine;
    engine.setTimesyncMethod(TimesyncMethod::PTP);
    engine.setTimesyncMaster(false);
    engine.receivedPTPSync(PORT_ID, SEQUENCE_ID, {2, 0}, CLOCK_ID_M1);
    engine.receivedPTPFollowUp(PORT_ID, SEQUENCE_ID, {1, 0}, CLOCK_ID_M1);
    engine.sentPTPDelayReq(PORT_ID, SEQUENCE_ID, {3, 0}, CLOCK_ID_S1);
    engine.receivedPTPDelayResp(PORT_ID, SEQUENCE_ID, {5, 0}, CLOCK_ID_M2, CLOCK_ID_S1);
    EXPECT_EQ(0 * 1000 * 1000, engine.getDelta(PORT_ID));
}

TEST_F(timesync_engine_test, slave_delta_invalid_src_port_id_3) {
    CTimesyncEngine engine;
    engine.setTimesyncMethod(TimesyncMethod::PTP);
    engine.setTimesyncMaster(false);
    engine.receivedPTPSync(PORT_ID, SEQUENCE_ID, {2, 0}, CLOCK_ID_M1);
    engine.receivedPTPFollowUp(PORT_ID, SEQUENCE_ID, {1, 0}, CLOCK_ID_M2);
    engine.sentPTPDelayReq(PORT_ID, SEQUENCE_ID, {3, 0}, CLOCK_ID_S1);
    engine.receivedPTPDelayResp(PORT_ID, SEQUENCE_ID, {5, 0}, CLOCK_ID_M2, CLOCK_ID_S1);
    EXPECT_EQ(0 * 1000 * 1000, engine.getDelta(PORT_ID));
}

TEST_F(timesync_engine_test, slave_delta_mixed_src_port_id) {
    CTimesyncEngine engine;
    engine.setTimesyncMethod(TimesyncMethod::PTP);
    engine.setTimesyncMaster(false);
    engine.receivedPTPSync(PORT_ID, SEQUENCE_ID, {2, 0}, CLOCK_ID_M1);
    engine.receivedPTPFollowUp(PORT_ID, SEQUENCE_ID, {1, 0}, CLOCK_ID_M1);
    engine.sentPTPDelayReq(PORT_ID, SEQUENCE_ID, {3, 0}, CLOCK_ID_S1);
    engine.receivedPTPDelayResp(PORT_ID, SEQUENCE_ID, {5, 0}, CLOCK_ID_M1, CLOCK_ID_S1);
    EXPECT_EQ(500 * 1000 * 1000, engine.getDelta(PORT_ID));

    engine.receivedPTPSync(PORT_ID, SEQUENCE_ID, {12, 0}, CLOCK_ID_M1);
    engine.receivedPTPFollowUp(PORT_ID, SEQUENCE_ID, {11, 0}, CLOCK_ID_M1);
    engine.sentPTPDelayReq(PORT_ID, SEQUENCE_ID, {13, 0}, CLOCK_ID_S1);
    engine.receivedPTPDelayResp(PORT_ID, SEQUENCE_ID, {15, 0}, CLOCK_ID_M2, CLOCK_ID_S1);
    EXPECT_EQ(500 * 1000 * 1000, engine.getDelta(PORT_ID));

    engine.receivedPTPDelayResp(PORT_ID, SEQUENCE_ID, {16, 0}, CLOCK_ID_M1, CLOCK_ID_S1);
    EXPECT_EQ(1000 * 1000 * 1000, engine.getDelta(PORT_ID));
}

TEST_F(timesync_engine_test, slave_delta_invalid_req_src_port_id) {
    CTimesyncEngine engine;
    engine.setTimesyncMethod(TimesyncMethod::PTP);
    engine.setTimesyncMaster(false);
    engine.receivedPTPSync(PORT_ID, SEQUENCE_ID, {2, 0}, CLOCK_ID_M1);
    engine.receivedPTPFollowUp(PORT_ID, SEQUENCE_ID, {1, 0}, CLOCK_ID_M1);
    engine.sentPTPDelayReq(PORT_ID, SEQUENCE_ID, {3, 0}, CLOCK_ID_S1);
    engine.receivedPTPDelayResp(PORT_ID, SEQUENCE_ID, {5, 0}, CLOCK_ID_M1, CLOCK_ID_S2);
    EXPECT_EQ(0 * 1000 * 1000, engine.getDelta(PORT_ID));
}

TEST_F(timesync_engine_test, test_rx_handle_pkt) {
    // Prepare node
    CGenNode *node = new CGenNode();
    node->m_type = CGenNode::TIMESYNC;

    // Prepare master engine
    CGlobalInfo::timesync_engine_setup();
    CTimesyncEngine *master_engine = CGlobalInfo::get_timesync_engine();
    master_engine->setTimesyncMethod(TimesyncMethod::PTP);
    master_engine->setTimesyncMaster(true);

    CGenNodeTimesync *timesync_node = (CGenNodeTimesync *)node;
    timesync_node->init();
    rte_mempool_t * mp1=utl_rte_mempool_create("big-const", 10, 2048, 32, 0, false);
    timesync_node->allocate_m(mp1);


    // Prepare slave engine
    CTimesyncEngine slave_engine;
    slave_engine.setTimesyncMaster(false);
    slave_engine.setTimesyncMethod(TimesyncMethod::PTP);
    RXTimesync rx = RXTimesync(&slave_engine, PORT_ID);

    // Confirm that all values are 0 before parsing any packets
    CTimesyncPTPData_t data = slave_engine.getClockInfo(PORT_ID, 0);
    EXPECT_EQ(0, data.t1.tv_sec);
    EXPECT_EQ(0, data.t1.tv_nsec);
    EXPECT_EQ(0, data.t2.tv_sec);
    EXPECT_EQ(0, data.t2.tv_nsec);
    EXPECT_EQ(0, data.t3.tv_sec);
    EXPECT_EQ(0, data.t3.tv_nsec);
    EXPECT_EQ(0, data.t4.tv_sec);
    EXPECT_EQ(0, data.t4.tv_nsec);


    // Master - push SYNC
    master_engine->pushNextMessage(PORT_ID, 0, PTP::Field::message_type::SYNC, {0, 0});
    // Slave - retrieve and parse SYNC
    rte_mbuf_t * pkt = timesync_node->get_pkt();  
    rx.handle_pkt(pkt, PORT_ID);

    data = slave_engine.getClockInfo(PORT_ID, 0);
    EXPECT_EQ(0, data.t1.tv_sec);
    EXPECT_EQ(0, data.t1.tv_nsec);
    EXPECT_NE(0, data.t2.tv_sec);
    EXPECT_NE(0, data.t2.tv_nsec);
    EXPECT_EQ(0, data.t3.tv_sec);
    EXPECT_EQ(0, data.t3.tv_nsec);
    EXPECT_EQ(0, data.t4.tv_sec);
    EXPECT_EQ(0, data.t4.tv_nsec);


    // Master - push FOLLOW UP
    timespec time =  {1111, 2222};
    master_engine->pushNextMessage(PORT_ID, 0, PTP::Field::message_type::FOLLOW_UP, time);
    // Slave - parse FOLLOW UP
    pkt = timesync_node->get_pkt();
    rx.handle_pkt(pkt, PORT_ID);

    data = slave_engine.getClockInfo(PORT_ID, 0);
    EXPECT_EQ(time.tv_sec, data.t1.tv_sec);
    EXPECT_EQ(time.tv_nsec, data.t1.tv_nsec);
    EXPECT_NE(0, data.t2.tv_sec);
    EXPECT_NE(0, data.t2.tv_nsec);
    EXPECT_EQ(0, data.t3.tv_sec);
    EXPECT_EQ(0, data.t3.tv_nsec);
    EXPECT_EQ(0, data.t4.tv_sec);
    EXPECT_EQ(0, data.t4.tv_nsec);


    // Master - push DELAY REQ
    timespec time4 = {3333, 4444};
    master_engine->pushNextMessage(PORT_ID, 0, PTP::Field::message_type::DELAY_RESP, time4);
    // Slave - parse DELAY REQ
    pkt = timesync_node->get_pkt();
    rx.handle_pkt(pkt, PORT_ID);

    data = slave_engine.getClockInfo(PORT_ID, 0);
    EXPECT_EQ(time.tv_sec, data.t1.tv_sec);
    EXPECT_EQ(time.tv_nsec, data.t1.tv_nsec);
    EXPECT_NE(0, data.t2.tv_sec);
    EXPECT_NE(0, data.t2.tv_nsec);
    EXPECT_EQ(0, data.t3.tv_sec);
    EXPECT_EQ(0, data.t3.tv_nsec);
    EXPECT_EQ(time4.tv_sec, data.t4.tv_sec);
    EXPECT_EQ(time4.tv_nsec, data.t4.tv_nsec);    
}

