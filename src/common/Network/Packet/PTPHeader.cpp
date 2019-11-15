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

#include "PTPHeader.h"

void PTPHeader::dump(FILE *fd) {
    fprintf(fd, "\nPTP Header");
    fprintf(fd, "\nMessageId 0x%.1X (%s), PTP Version %d, MessageLength %d", getMessageId(),
            MessageType::interpretMessageType(getMessageId()), getVersion(), getLength());
    fprintf(fd, "\nSubdomainNumber %d, Flags %.4X", getSubdomainNumber(), getFlags());
    fprintf(fd, "\nCorrection 0x%.16lX", getCorrection());
    fprintf(fd, "\nClockIdentity 0x%.16lX, SourcePortId %d", getClockIdentity(), getSourcePortId());
    fprintf(fd, "\nSequenceId %d, Control %d, LogMessagePeriod %d", getSequenceId(), getControl(),
            getLogMessagePeriod());
    fprintf(fd, "\n");
}

char *PTPHeader::MessageType::interpretMessageType(uint8_t messageType) {
    switch (messageType) {
    case SYNC:
        return (char *)"SYNC";
        break;
    case DELAY_REQ:
        return (char *)"DELAY_REQ";
        break;
    case FOLLOW_UP:
        return (char *)"FOLLOW_UP";
        break;
    case DELAY_RESP:
        return (char *)"DELAY_RESP";
        break;
    default:
        return (char *)NULL;
        break;
    }
}