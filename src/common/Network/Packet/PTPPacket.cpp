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

void PTP::Header::dump(FILE *fd) {
    fprintf(fd, "\nPTP Header");
    fprintf(fd, "\nMessageId 0x%.1X (%s), TransportSpecific 0x%.1X, PTP Version %d, MessageLength %d",
            trn_and_msg.msg_type_raw(), trn_and_msg.msg_type_str(), trn_and_msg.trans_spec_raw(),
            static_cast<int>(*ver), static_cast<int>(*message_len));
    fprintf(fd, "\nSubdomainNumber %d, Flags %.4X", *domain_number, *flag_field);
    fprintf(fd, "\nCorrection 0x%.16lX", *correction);
    fprintf(fd, "\nClockIdentity 0x%.16lX, SourcePortId %d", source_port_id.clock_id(),
            static_cast<int>(source_port_id.port_number()));
    fprintf(fd, "\nSequenceId %d, Control %d, LogMessagePeriod %d", static_cast<int>(*seq_id),
            static_cast<int>(*control), static_cast<int>(*log_message_interval));
    fprintf(fd, "\n");
}

void PTP::BasePacket::dump(FILE *fd) {
    fprintf(fd, "\nPTP Packet ()");
    fprintf(
        fd, "\nSeconds (msb) 0x%.4X (%u), Seconds (lsb) (0x%.8lX (%lu)), Nanoseconds (0x%.8lX (%lu))",
        static_cast<unsigned int>(*(origin_timestamp.sec_msb)), static_cast<unsigned int>(*(origin_timestamp.sec_msb)),
        static_cast<unsigned long int>(*(origin_timestamp.sec_lsb)),
        static_cast<unsigned long int>(*(origin_timestamp.sec_lsb)),
        static_cast<unsigned long int>(*(origin_timestamp.ns)), static_cast<unsigned long int>(*(origin_timestamp.ns)));
    fprintf(fd, "\nTimestamp %ld.%ld", static_cast<unsigned long int>(origin_timestamp.get_timestamp().tv_sec),
            static_cast<unsigned long int>(origin_timestamp.get_timestamp().tv_nsec));
    fprintf(fd, "\n");
}

void PTP::DelayedRespPacket::dump(FILE *fd) {
    fprintf(fd, "\nPTP Packet ()");
    fprintf(
        fd, "\nSeconds (msb) 0x%.4X (%u), Seconds (lsb) (0x%.8lX (%lu)), Nanoseconds (0x%.8lX (%lu))",
        static_cast<unsigned int>(*(origin_timestamp.sec_msb)), static_cast<unsigned int>(*(origin_timestamp.sec_msb)),
        static_cast<unsigned long int>(*(origin_timestamp.sec_lsb)),
        static_cast<unsigned long int>(*(origin_timestamp.sec_lsb)),
        static_cast<unsigned long int>(*(origin_timestamp.ns)), static_cast<unsigned long int>(*(origin_timestamp.ns)));
    fprintf(fd, "\nTimestamp %ld.%ld", static_cast<unsigned long int>(origin_timestamp.get_timestamp().tv_sec),
            static_cast<unsigned long int>(origin_timestamp.get_timestamp().tv_nsec));
    fprintf(fd, "\nRequesting ClockIdentity 0x%.16lX, Requesting SourcePortId %d",
            static_cast<unsigned long int>(req_clock_identity.clock_id()),
            static_cast<unsigned int>(req_clock_identity.port_number()));
    fprintf(fd, "\n");
}

