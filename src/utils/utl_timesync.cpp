/*
 Mateusz Neumann, Codilime
*/

/*
Copyright (c) 2019 Codilime Sp. z o. o.

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

#include "utl_timesync.h"
#include "trex_global.h"

#include <unistd.h>


dsec_t do_timesync(dsec_t cur_time) {
    if (CGlobalInfo::m_options.m_timesync_method == CParserOption::TIMESYNC_NONE) {
        return cur_time;
    }

    if (CGlobalInfo::m_options.m_timesync_method == CParserOption::TIMESYNC_PTP) {
        printf("Syncing time with PTP method (master side).\n");
        #ifdef _DEBUG
        printf("PTP time synchronisation is currently not supported (but we are working on that).\n");
        #endif
        return cur_time;
    }

    return cur_time;
}
