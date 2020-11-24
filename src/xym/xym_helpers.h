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
#ifndef LEDGER_APP_XYM_XYMHELPERS_H
#define LEDGER_APP_XYM_XYMHELPERS_H

#include <os.h>
#include <cx.h>
#include <os_io_seproxyhal.h>
#include <stdbool.h>

#define XYM_TXN_TRANSFER 0x4154
#define XYM_TXN_REGISTER_NAMESPACE 0x414E
#define XYM_TXN_ADDRESS_ALIAS 0x424E
#define XYM_TXN_MOSAIC_ALIAS 0x434E
#define XYM_TXN_MOSAIC_DEFINITION 0x414D
#define XYM_TXN_MOSAIC_SUPPLY_CHANGE 0x424D
#define XYM_TXN_MODIFY_MULTISIG_ACCOUNT 0x4155
#define XYM_TXN_AGGREGATE_COMPLETE 0x4141
#define XYM_TXN_AGGREGATE_BONDED 0x4241
#define XYM_TXN_ACCOUNT_METADATA 0X4144
#define XYM_TXN_MOSAIC_METADATA 0X4244
#define XYM_TXN_NAMESPACE_METADATA 0X4344
#define XYM_TXN_HASH_LOCK 0x4148
#define XYM_TXN_SECRET_LOCK 0x4152
#define XYM_TXN_SECRET_PROOF 0x4252
#define XYM_TXN_MODIFY_ACCOUNT_PROPERTY_ADDRESS 0x4150
#define XYM_TXN_MODIFY_ACCOUNT_PROPERTY_MOSAIC 0x4250
#define XYM_TXN_MODIFY_ACCOUNT_PROPERTY_ENTITY_TYPE 0x4350

#define XYM_MOSAIC_ID 0x5B66E76BECAD0860
#define AMOUNT_MAX_SIZE 17
#define XYM_ADDRESS_LENGTH 24
#define XYM_PRETTY_ADDRESS_LENGTH 39
#define XYM_PUBLIC_KEY_LENGTH 32
#define XYM_PRIVATE_KEY_LENGTH 32
#define XYM_TRANSACTION_HASH_LENGTH 32
#define XYM_PKG_GETPUBLICKEY_LENGTH 22

void xym_print_amount(uint64_t amount, uint8_t divisibility, char *asset, char *out);
void xym_public_key_and_address(cx_ecfp_public_key_t *inPublicKey, uint8_t inNetworkId, uint8_t *outPublicKey, char *outAddress, uint8_t outLen);

#endif //LEDGER_APP_XYM_XYMHELPERS_H