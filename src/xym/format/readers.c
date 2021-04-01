/*******************************************************************************
*   XYM Wallet
*   (c) 2017 Ledger
*   (c) 2020 FDS
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/
#include <string.h>
#include "readers.h"

int8_t read_int8(const uint8_t *src) {
    return (int8_t) *((uint8_t*) src);
}

int16_t read_int16(const uint8_t *src) {
    return (int16_t) *((uint8_t*) src);
}

uint8_t read_uint8(const uint8_t *src) {
    return (uint8_t) *((uint8_t *)src);
}

uint16_t read_uint16(const uint8_t *src) {
    return (uint16_t) *((uint16_t *)src);
}

uint16_t read_uint32(const uint8_t *src) {
    return (uint32_t) *((uint32_t *)src);
}

uint64_t read_uint64(const uint8_t *src) {
    return (uint64_t) *((uint32_t *)src);
}
