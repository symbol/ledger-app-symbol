/*******************************************************************************
*   XYM Wallet
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
#ifndef LEDGER_APP_XYM_FIELDS_H
#define LEDGER_APP_XYM_FIELDS_H

#include <stdint.h>
#include <os.h>
#include <string.h>

// Normal field types
#define STI_INT8 0x01
#define STI_UINT8 0x02
#define STI_UINT16 0x03
#define STI_UINT32 0x04
#define STI_UINT64 0x05
#define STI_HASH256 0x06
#define STI_STR 0x17
// Custom field types
#define STI_XYM 0xA0
#define STI_MOSAIC_COUNT 0xA1
#define STI_MOSAIC_CURRENCY 0xA2
#define STI_MESSAGE 0xA3
#define STI_ADDRESS 0xA4

// Small collection of used field IDs
#define XYM_INT8_MAM_REMOVAL_DELTA 0x01
#define XYM_INT8_MAM_APPROVAL_DELTA 0x02

#define XYM_UINT8_MOSAIC_COUNT 0x10
#define XYM_UINT8_NS_REG_TYPE 0x11
#define XYM_UINT8_AA_TYPE 0x12
#define XYM_UINT8_TXN_MESSAGE_TYPE 0x13
#define XYM_UINT8_MSC_ACTION 0x14
#define XYM_UINT8_MAM_ADD_COUNT 0x15
#define XYM_UINT8_MAM_DEL_COUNT 0x16
#define XYM_UINT8_MD_SUPPLY_FLAG 0x17
#define XYM_UINT8_MD_TRANS_FLAG 0x18
#define XYM_UINT8_MD_RESTRICT_FLAG 0x19
#define XYM_UINT8_MD_DIV 0x1A

#define XYM_UINT16_TRANSACTION_TYPE 0x30
#define XYM_UINT16_INNER_TRANSACTION_TYPE 0x31

#define XYM_UINT64_TXN_FEE 0x70
#define XYM_UINT64_DURATION 0x71
#define XYM_UINT64_PARENTID 0x72
#define XYM_UINT64_NS_ID 0x73
#define XYM_UINT64_MOSAIC_ID 0x74
#define XYM_UINT64_MSC_AMOUNT 0x75
#define XYM_UINT64_ROOT_RENTAIL_FEE 0x76
#define XYM_UINT64_SUB_RENTAIL_FEE 0x77

#define XYM_STR_RECIPIENT_ADDRESS 0x90
#define XYM_STR_TXN_MESSAGE 0x91
#define XYM_STR_NAMESPACE 0x92
#define XYM_STR_ADDRESS 0x93

#define XYM_HASH256_AGG_HASH 0xB0
#define XYM_HASH256_HL_HASH 0xB1

#define XYM_MOSAICT_HL_QUANTITY 0xD0
#define XYM_MOSAICT_AMOUNT 0xD1

typedef struct {
    uint8_t id;
    uint8_t dataType;
    uint16_t length;
    uint8_t *data;
} field_t;

// Simple macro for building more readable switch statements
#define CASE_FIELDNAME(v,src) case v: snprintf(dst, MAX_FIELDNAME_LEN, "%s", src); return;

void resolve_fieldname(field_t *field, char* dst);

#endif //LEDGER_APP_XYM_FIELDS_H
