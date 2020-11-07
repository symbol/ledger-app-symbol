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
#include <os_io_seproxyhal.h>
#include <string.h>
#include "readers.h"

char int_to_number_char(uint64_t value) {
    if (value > 9) {
        return '?';
    }

    return (char) ('0' + value);
}

void sprintf_number(char *dst, uint16_t len, uint64_t value) {
    uint16_t numDigits = 0, i;
    uint64_t base = 1;
    while (base <= value) {
        base *= 10;
        if (base < 10) {
            THROW(EXCEPTION_OVERFLOW);
        }
        numDigits++;
    }
    if (numDigits > len - 1) {
        THROW(EXCEPTION_OVERFLOW);
    }
    base /= 10;
    for (i=0; i<numDigits; i++) {
        dst[i] = int_to_number_char((value / base) % 10);
        base /= 10;
    }
    dst[i] = '\0';
}

void sprintf_hex(char *dst, uint16_t maxLen, uint8_t *src, uint16_t dataLength, uint8_t reverse) {
    if (2 * dataLength > maxLen - 1) {
        THROW(EXCEPTION_OVERFLOW);
    }
    for (uint16_t i = 0; i < dataLength; i++) {
        SPRINTF(dst + 2 * i, "%02X", reverse==1?src[dataLength-1-i]:src[i]);
    }
    dst[2*dataLength] = '\0';
}

void snprintf_ascii_ex(char *dst, uint16_t pos, uint16_t maxLen, uint8_t *src, uint16_t dataLength) {
    if (dataLength + pos > maxLen - 1) {
        THROW(EXCEPTION_OVERFLOW);
    }
    char *tmpCh = (char *) src;
    uint16_t k = 0, l = 0;
    for (uint8_t j=0; j < dataLength; j++){
        if (tmpCh[j] < 32 || tmpCh[j] > 126) {
            k++;
            if (k==1) {
                dst[pos + l] = '?';
                l++;
            } else if (k==2) {
                k = 0;
            }
        } else {
            k = 0;
            dst[pos + l] = tmpCh[j];
            l++;
        }
    }
    dst[pos + l] = '\0';
}

void sprintf_ascii(char *dst, uint16_t maxLen, uint8_t *src, uint16_t dataLength) {
    snprintf_ascii_ex(dst, 0, maxLen, src, dataLength);
}

void snprintf_ascii(char *dst, uint16_t pos, uint16_t maxLen, uint8_t *src, uint16_t dataLength) {
    if (dataLength + pos > maxLen - 1) {
        THROW(EXCEPTION_OVERFLOW);
    }
    char *tmpCh = (char *) src;
    for (uint16_t j=0; j < dataLength; j++) {
        if (tmpCh[j] < 32 || tmpCh[j] > 126) {
            dst[pos+j] = '?';
        } else {
            dst[pos+j] = tmpCh[j];
        }
    }
    dst[dataLength + pos] = '\0';
}

void sprintf_mosaic(char *dst, uint16_t maxLen, mosaic_t *mosaic, char *asset) {
    sprintf_number(dst, maxLen, mosaic->amount);
    strcat(dst, " ");
    strcat(dst, asset);
    strcat(dst, " 0x");
    uint16_t len = strlen(dst);
    uint8_t* mosaicId = (uint8_t*) &mosaic->mosaicId;
    char* mosaicHex = dst + len;
    sprintf_hex(mosaicHex, maxLen - len, mosaicId, sizeof(uint64_t), 1);
}

uint64_t read_uint64(uint8_t *src) {
    return (uint64_t) *((uint32_t *)src);
}

uint8_t read_uint8(uint8_t *src) {
    return (uint8_t) *((uint8_t *)src);
}

uint16_t read_uint16(uint8_t *src) {
    return (uint16_t) *((uint16_t *)src);
}

uint32_t read_uint32(uint8_t *src) {
    return (uint32_t) *((uint32_t *)src);
}

int8_t read_int8(uint8_t *src) {
    return (int8_t) *((uint8_t*) src);
}
