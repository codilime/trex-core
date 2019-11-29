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

#define PORT_ID 0
#define SEQUENCE_ID 1
#define MAX_SEC 2147483647

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
