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

class MPLSHeader {
public:
    uint32_t getLabel() {
        return (uint32_t)label;
    }

    bool getBottomOfStack() {
        return (bottom_of_stack != 1 ? true : false);
    }

private:
    uint32_t label : 20;
    uint32_t tc : 3;
    uint32_t bottom_of_stack : 1;
    uint32_t ttl : 8;
} __attribute__((packed));

#endif 

