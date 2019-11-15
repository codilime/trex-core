/*
Copyright (c) 2019 Mateusz Neumann, Codilime

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

#include "PTPPacket.h"

void PTPPacket::dump(FILE *fd) {
    fprintf(fd, "\nPTP Packet ()");
    fprintf(fd, "\nSeconds (msb) 0x%.4X (%u), Seconds (lsb) (0x%.8X (%lu)), Nanoseconds (0x%.8X (%lu))",
            getOriginSecondsMsb(), getOriginSecondsMsb(), getOriginSecondsLsb(), getOriginSecondsLsb(),
            getOriginNanoseconds(), getOriginNanoseconds());
    fprintf(fd, "\nTimestamp %g", getOriginTimestamp());
    fprintf(fd, "\n");
}

void PTPPacketDelayedResp::dump(FILE *fd) {
    fprintf(fd, "\nPTP Packet ()");
    fprintf(fd, "\nSeconds (msb) 0x%.4X (%u), Seconds (lsb) (0x%.8X (%lu)), Nanoseconds (0x%.8X (%lu))",
            getOriginSecondsMsb(), getOriginSecondsMsb(), getOriginSecondsLsb(), getOriginSecondsLsb(),
            getOriginNanoseconds(), getOriginNanoseconds());
    fprintf(fd, "\nTimestamp %g", getOriginTimestamp());
    fprintf(fd, "\nRequesting ClockIdentity 0x%.16lX, Requesting SourcePortId %d", getReqClockIdentity(),
            getReqSourcePortId());
    fprintf(fd, "\n");
}
