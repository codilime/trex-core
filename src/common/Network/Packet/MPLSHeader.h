/*
Copyright (c) 2020-2020 Codilime, Sp. z o.o.

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

#ifndef _MPLS_HEADER_H_
#define _MPLS_HEADER_H_

#include "PacketHeaderBase.h"

#ifndef likely
#define likely(x)  __builtin_expect((x),1)
#endif /* likely */

#define MPLS_HDR_LEN 4

#define LABEL_MASK 0x000FFFFF
#define TC_MASK 0x00700000
#define BOS_MASK 0x00800000
#define TTL_MASK 0xFF000000

class MPLSHeader {
public:
    uint32_t getLabel() {
        return (PKT_NTOHL(data) & LABEL_MASK);
    }

    uint8_t getTrafficClass() {
        return ((PKT_NTOHL(data) & TC_MASK) >> 20);
    }

    bool getBottomOfStack() {
        return ((PKT_NTOHL(data) & BOS_MASK) > 1 ? true : false);
    }

    uint8_t getTTL() {
        return (PKT_NTOHL(data) & TTL_MASK);
    }

//private:
    uint32_t data;
} __attribute__((packed));

#endif 

