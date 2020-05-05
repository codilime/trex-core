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

#ifndef _GRE_HEADER_H_
#define _GRE_HEADER_H_

#include "PacketHeaderBase.h"

#ifndef likely
#define likely(x)  __builtin_expect((x),1)
#endif /* likely */

#define GRE_HDR_LEN 4

class GREHeader {
public:
    uint16_t getProto() {
        return PKT_HTONS(proto);
    }

private:
    uint16_t c : 1;
    uint16_t reserved : 1;
    uint16_t k : 1;
    uint16_t s : 1;
    uint16_t reserved0 : 6;
    uint16_t version : 3;

    uint16_t proto;
    uint16_t checksum;
    uint16_t reserved1;

} __attribute__((packed));

#endif
