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
#include "printers.h"

int snprintf_number(char *dst, uint16_t len, uint64_t value) {
    char *p = dst;

    // First, compute the address of the last digit to be written.
    uint64_t shifter = value;
    do {
        p++;
        shifter /= 10;
    } while (shifter);

    if (p > dst + len - 1) {
        return E_NOT_ENOUGH_DATA;
    }
    int n = p - dst;

    // Now write string representation, right to left.
    *p-- = 0;
    do {
        *p-- = '0' + (value % 10);
        value /= 10;
    } while (value);
    return n;
}

int snprintf_hex(char *dst, uint16_t maxLen, const uint8_t *src, uint16_t dataLength, uint8_t reverse) {
    if (2 * dataLength > maxLen - 1 || maxLen < 1 || dataLength < 1) {
        return E_NOT_ENOUGH_DATA;
    }
    for (uint16_t i = 0; i < dataLength; i++) {
        snprintf(dst + 2 * i, maxLen - 2 * i, "%02X", reverse==1?src[dataLength-1-i]:src[i]);
    }
    dst[2*dataLength] = '\0';
    return 2*dataLength;
}

int snprintf_ascii(char *dst, uint16_t maxLen, const uint8_t *src, uint16_t dataLength) {
    if (dataLength > maxLen - 1 || maxLen < 1 || dataLength < 1) {
        return E_NOT_ENOUGH_DATA;
    }
    char *tmpCh = (char *) src;
    uint16_t k = 0, l = 0;
    for (uint16_t j=0; j < dataLength; j++){
        if (tmpCh[j] < 32 || tmpCh[j] > 126) {
            k++;
            if (k==1) {
                dst[l] = '?';
                l++;
            } else if (k==2) {
                k = 0;
            }
        } else {
            k = 0;
            dst[l] = tmpCh[j];
            l++;
        }
    }
    dst[l] = '\0';
    return l;
}

int snprintf_mosaic(char *dst, uint16_t maxLen, mosaic_t *mosaic, char *asset) {
    if(snprintf_number(dst, maxLen, mosaic->amount) < 1) {
        return E_NOT_ENOUGH_DATA;
    };
    strcat(dst, " ");
    strcat(dst, asset);
    strcat(dst, " 0x");
    uint16_t len = strlen(dst);
    uint8_t* mosaicId = (uint8_t*) &mosaic->mosaicId;
    char* mosaicHex = dst + len;
    if(snprintf_hex(mosaicHex, maxLen - len, mosaicId, sizeof(uint64_t), 1) < 1) {
        return E_NOT_ENOUGH_DATA;
    };
    return strlen(dst);
}
