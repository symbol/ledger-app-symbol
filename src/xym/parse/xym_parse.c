/*******************************************************************************
*    XYM Wallet
*    (c) 2020 FDS
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

#include "xym_parse.h"
#include "apdu/global.h"
#include "xym/xym_helpers.h"

#define TXN_HEADER_LENGTH           32
typedef struct {
    uint8_t recipientAddress[XYM_ADDRESS_LENGTH];
    uint16_t messageSize;
    uint8_t mosaicsCount;
    uint32_t reserved1;
    uint8_t reserved2;
} txn_header_t;

#define MOSAIC_DEFINITION_DATA_LENGTH           22
typedef struct {
    uint64_t mosaicId;
    uint64_t duration;
    uint32_t nonce;
    uint8_t flags;
    uint8_t divisibility;
} mosaic_definition_data_t;

#define MOSAIC_SUPPLY_CHANGE_DATA_LENGTH        17
typedef struct {
    mosaic_t mosaic;
    uint8_t action;
} mosaic_supply_change_data_t;

#define INNER_TX_HEADER_LENGTH      48
typedef struct {
    uint32_t size;
    uint32_t reserve1;
    uint8_t signerPublicKey[XYM_PUBLIC_KEY_LENGTH];
    uint32_t reserve2;
    uint8_t version;
    uint8_t network;
    uint16_t innerTxType;
} inner_tx_header_t;

#define AGGREGATE_TXN_LENGTH        40
typedef struct {
    uint8_t transactionHash[XYM_TRANSACTION_HASH_LENGTH];
    uint32_t payloadSize;
    uint32_t reserse;
} aggregate_txn_t;

#define NS_REGISTRATION_HEADER_LENGTH 18
typedef struct {
    uint64_t duration;
    uint64_t namespaceId;
    uint8_t registrationType;
    uint8_t nameSize;
} ns_header_t;

#define ADDRESS_ALIAS_HEADER_LENGTH 33
typedef struct {
    uint64_t namespaceId;
    uint8_t address[XYM_ADDRESS_LENGTH];
    uint8_t aliasAction;
} aa_header_t;

#define MOSAIC_ALIAS_HEADER_LENGTH  17
typedef struct {
    uint64_t namespaceId;
    uint64_t mosaicId;
    uint8_t aliasAction;
} ma_header_t;

#define MUTLISIG_ACCOUNT_HEADER_LENGTH 8
typedef struct {
    int8_t minRemovalDelta;
    int8_t minApprovalDelta;
    uint8_t addressAdditionsCount;
    uint8_t addressDeletionsCount;
    uint32_t reserve;
} multisig_account_t;

#define HASH_LOCK_HEADER_LENGTH     56
typedef struct {
    mosaic_t mosaic;
    uint64_t blockDuration;
    uint8_t aggregateBondedHash[XYM_TRANSACTION_HASH_LENGTH];
} hl_header_t;

typedef struct {
    uint8_t transactionHash[XYM_TRANSACTION_HASH_LENGTH];
    uint8_t reserved1;
    uint8_t networkType;
    uint16_t transactionType;
} common_header_t;

bool has_data(parse_context_t *context, uint32_t numBytes) {
    return context->offset + numBytes - 1 < context->length;
}

field_t *get_field(parse_context_t *context, int idx) {
    return &context->result.fields[idx];
}

field_t* _set_field_data(field_t* field, uint8_t id, uint8_t data_type, uint16_t length, uint8_t* data) {
    field->id = id;
    field->dataType = data_type;
    field->length = length;
    field->data = data;
    return field;
}

field_t* set_field_data(parse_context_t *context, int idx, uint8_t id, uint8_t data_type, uint16_t length, uint8_t* data) {
    return _set_field_data(get_field(context, idx), id, data_type, length, data);
}

field_t *add_new_field(parse_context_t *context, uint8_t id, uint8_t data_type, uint16_t length, uint8_t* data) {
    return set_field_data(context, context->result.numFields++, id, data_type, length, data);
}

uint8_t* read_data(parse_context_t *context, uint32_t numBytes) {
    if (has_data(context, numBytes)) {
        uint32_t offset = context->offset;
        context->offset += numBytes;
        return context->data + offset;
    } else {
        THROW(EXCEPTION_OVERFLOW);
    }
}

void advance_position(parse_context_t *context, uint32_t numBytes) {
    if (has_data(context, numBytes)) {
        context->offset += numBytes;
    } else {
        THROW(EXCEPTION_OVERFLOW);
    }
}

void parse_transfer_txn_content(parse_context_t *context, bool isMultisig) {
    // get header first
    txn_fee_t *fee = NULL;
    if (!isMultisig) {
        fee = (txn_fee_t*) read_data(context, sizeof(txn_fee_t));
    }
    txn_header_t *txn = (txn_header_t*) read_data(context, TXN_HEADER_LENGTH);
    uint32_t length = txn->mosaicsCount * sizeof(mosaic_t) + txn->messageSize;
    if (has_data(context, length)) {
        // Show Recipient address
        add_new_field(context, XYM_STR_RECIPIENT_ADDRESS, STI_ADDRESS, XYM_ADDRESS_LENGTH, (uint8_t*) txn->recipientAddress);
        // Show sent mosaic count field
        add_new_field(context, XYM_UINT8_MOSAIC_COUNT, STI_UINT8, sizeof(uint8_t), (uint8_t*) &txn->mosaicsCount);
        // Show mosaics amount
        for (uint8_t i = 0; i < txn->mosaicsCount; i++) {
            add_new_field(context, XYM_MOSAICT_AMOUNT, STI_MOSAIC_CURRENCY, sizeof(mosaic_t), read_data(context, sizeof(mosaic_t)));
        }
        if (txn->messageSize == 0) {
            // Show Empty Message
            add_new_field(context, XYM_STR_TXN_MESSAGE, STI_MESSAGE, txn->messageSize, NULL);
        } else {
            // Show Message Type
            add_new_field(context, XYM_UINT8_TXN_MESSAGE_TYPE, STI_UINT8, sizeof(uint8_t), read_data(context, sizeof(uint8_t)));
            // Show Message
            add_new_field(context, XYM_STR_TXN_MESSAGE, STI_MESSAGE, txn->messageSize - 1, read_data(context, txn->messageSize - 1));
        }
        if (!isMultisig) {
            // Show fee
            add_new_field(context, XYM_UINT64_TXN_FEE, STI_XYM, sizeof(uint64_t), (uint8_t*) &fee->maxFee);
        }
    } else {
        THROW(EXCEPTION_OVERFLOW);
    }
}

void parse_mosaic_definition_txn_content(parse_context_t *context, bool isMultisig) {
    // get header first
    txn_fee_t *fee = NULL;
    if (!isMultisig) {
        fee = (txn_fee_t*) read_data(context, sizeof(txn_fee_t));
    }
    mosaic_definition_data_t *txn = (mosaic_definition_data_t*) read_data(context, MOSAIC_DEFINITION_DATA_LENGTH);
    // Show mosaic id
    add_new_field(context, XYM_UINT64_MOSAIC_ID, STI_UINT64, sizeof(uint64_t), (uint8_t*) &txn->mosaicId);
    // Show duration
    add_new_field(context, XYM_UINT64_DURATION, STI_UINT64, sizeof(uint64_t), (uint8_t*) &txn->duration);
    // Show mosaic flag (Transferable)
    add_new_field(context, XYM_UINT8_MD_TRANS_FLAG, STI_UINT8, sizeof(uint8_t), (uint8_t*) &txn->flags);
    // Show mosaic flag (Supply mutable)
    add_new_field(context, XYM_UINT8_MD_SUPPLY_FLAG, STI_UINT8, sizeof(uint8_t), (uint8_t*) &txn->flags);
    // Show mosaic flag (Restrictable)
    add_new_field(context, XYM_UINT8_MD_RESTRICT_FLAG, STI_UINT8, sizeof(uint8_t), (uint8_t*) &txn->flags);
}

void parse_mosaic_supply_change_txn_content(parse_context_t *context, bool isMultisig) {
    // get header first
    txn_fee_t *fee = NULL;
    if (!isMultisig) {
        fee = (txn_fee_t*) read_data(context, sizeof(txn_fee_t));
    }
    mosaic_supply_change_data_t *txn = (mosaic_supply_change_data_t*) read_data(context, MOSAIC_SUPPLY_CHANGE_DATA_LENGTH);
    // Show mosaic id
    add_new_field(context, XYM_UINT64_MOSAIC_ID, STI_UINT64, sizeof(uint64_t), (uint8_t*) &txn->mosaic.mosaicId);
    // Show supply change action
    add_new_field(context, XYM_UINT8_MSC_ACTION, STI_UINT8, sizeof(uint8_t), (uint8_t*) &txn->action);
    // Show amount
    add_new_field(context, XYM_UINT64_MSC_AMOUNT, STI_UINT64, sizeof(mosaic_t), (uint8_t*) &txn->mosaic.amount);
}

void parse_multisig_account_modification_txn_content(parse_context_t *context, bool isMultisig) {
    // get header first
    txn_fee_t *fee = NULL;
    if (!isMultisig) {
        fee = (txn_fee_t*) read_data(context, sizeof(txn_fee_t));
    }
    multisig_account_t *txn = (multisig_account_t*) read_data(context, MUTLISIG_ACCOUNT_HEADER_LENGTH);
    // Show address additions count
    add_new_field(context, XYM_UINT8_MAM_ADD_COUNT, STI_UINT8, sizeof(uint8_t), (uint8_t*) &txn->addressAdditionsCount);
    // Show list of addition address
    for (uint8_t i = 0; i < txn->addressAdditionsCount; i++) {
        add_new_field(context, XYM_STR_ADDRESS, STI_ADDRESS, XYM_ADDRESS_LENGTH, read_data(context, XYM_ADDRESS_LENGTH));
    }
    // Show address deletions count
    add_new_field(context, XYM_UINT8_MAM_DEL_COUNT, STI_UINT8, sizeof(uint8_t), (uint8_t*) &txn->addressDeletionsCount);
    // Show list of addition address
    for (uint8_t i = 0; i < txn->addressDeletionsCount; i++) {
        add_new_field(context, XYM_STR_ADDRESS, STI_ADDRESS, XYM_ADDRESS_LENGTH, read_data(context, XYM_ADDRESS_LENGTH));
    }
    // Show min approval delta
    add_new_field(context, XYM_INT8_MAM_APPROVAL_DELTA, STI_INT8, sizeof(int8_t), (uint8_t*) &txn->minApprovalDelta);
    // Show min removal delta
    add_new_field(context, XYM_INT8_MAM_REMOVAL_DELTA, STI_INT8, sizeof(int8_t), (uint8_t*) &txn->minRemovalDelta);
}

void parse_namespace_registration_txn_content(parse_context_t *context, bool isMultisig) {
    // get header first
    txn_fee_t *fee = NULL;
    if (!isMultisig) {
        fee = (txn_fee_t*) read_data(context, sizeof(txn_fee_t));
    }
    ns_header_t *txn = (ns_header_t*) read_data(context, NS_REGISTRATION_HEADER_LENGTH);
    if (has_data(context, txn->nameSize)) {
        // Show namespace reg type
        add_new_field(context, XYM_UINT8_NS_REG_TYPE, STI_UINT8, sizeof(uint8_t), (uint8_t*) &txn->registrationType);
        // Show namespace/sub-namespace name
        add_new_field(context, XYM_STR_NAMESPACE, STI_STR, txn->nameSize, read_data(context, txn->nameSize));
        // Show Duration/ParentID
        add_new_field(context, txn->registrationType==0?XYM_UINT64_DURATION:XYM_UINT64_PARENTID, STI_UINT64,
            sizeof(uint64_t), (uint8_t*) &txn->duration);
        if (!isMultisig) {
            // Show fee
            add_new_field(context, XYM_UINT64_TXN_FEE, STI_XYM, sizeof(uint64_t), (uint8_t*) &fee->maxFee);
        }
    } else {
        THROW(EXCEPTION_OVERFLOW);
    }
}

void parse_address_alias_txn_content(parse_context_t *context, bool isMultisig) {
    // get header first
    txn_fee_t *fee = NULL;
    if (!isMultisig) {
        fee = (txn_fee_t*) read_data(context, sizeof(txn_fee_t));
    }
    aa_header_t *txn = (aa_header_t*) read_data(context, ADDRESS_ALIAS_HEADER_LENGTH);
    // Show alias type
    add_new_field(context, XYM_UINT8_AA_TYPE, STI_UINT8, sizeof(uint8_t), (uint8_t*) &txn->aliasAction);
    // Show namespace id
    add_new_field(context, XYM_UINT64_NS_ID, STI_UINT64, sizeof(uint64_t), (uint8_t*) &txn->namespaceId);
    // Show Recipient address
    add_new_field(context, XYM_STR_ADDRESS, STI_ADDRESS, XYM_ADDRESS_LENGTH, (uint8_t*) txn->address);
    if (!isMultisig) {
        // Show fee
        add_new_field(context, XYM_UINT64_TXN_FEE, STI_XYM, sizeof(uint64_t), (uint8_t*) &fee->maxFee);
    }
}

void parse_mosaic_alias_txn_content(parse_context_t *context, bool isMultisig) {
    // get header first
    txn_fee_t *fee = NULL;
    if (!isMultisig) {
        fee = (txn_fee_t*) read_data(context, sizeof(txn_fee_t));
    }
    ma_header_t *txn = (ma_header_t*) read_data(context, MOSAIC_ALIAS_HEADER_LENGTH);
    // Show alisac type
    add_new_field(context, XYM_UINT8_AA_TYPE, STI_UINT8, sizeof(uint8_t), (uint8_t*) &txn->aliasAction);
    // Show namespace id
    add_new_field(context, XYM_UINT64_NS_ID, STI_UINT64, sizeof(uint64_t), (uint8_t*) &txn->namespaceId);
    // Show mosaic
    add_new_field(context, XYM_UINT64_MOSAIC_ID, STI_UINT64, sizeof(uint64_t), (uint8_t*) &txn->mosaicId);
    if (!isMultisig) {
        // Show fee
        add_new_field(context, XYM_UINT64_TXN_FEE, STI_XYM, sizeof(uint64_t), (uint8_t*) &fee->maxFee);
    }
}

void parse_hash_lock_txn_content(parse_context_t *context, bool isMultisig) {
    // get header first
    txn_fee_t *fee = NULL;
    if (!isMultisig) {
        fee = (txn_fee_t*) read_data(context, sizeof(txn_fee_t));
    }
    hl_header_t *txn = (hl_header_t*) read_data(context, HASH_LOCK_HEADER_LENGTH);
    // Show lock quantity
    add_new_field(context, XYM_MOSAICT_HL_QUANTITY, STI_MOSAIC_CURRENCY, sizeof(mosaic_t), (uint8_t*) &txn->mosaic);
    // Show duration
    add_new_field(context, XYM_UINT64_DURATION, STI_UINT64, sizeof(uint64_t), (uint8_t*) &txn->blockDuration);
    // Show transaction hash
    add_new_field(context, XYM_HASH256_HL_HASH, STI_HASH256, XYM_TRANSACTION_HASH_LENGTH, (uint8_t*) &txn->aggregateBondedHash);
    if (!isMultisig) {
        // Show tx fee
        add_new_field(context, XYM_UINT64_TXN_FEE, STI_XYM, sizeof(uint64_t), (uint8_t*) &fee->maxFee);
    }
}

void parse_inner_txn_content(parse_context_t *context, uint32_t len) {
    uint32_t totalSize = 0;
    do {
        // get header first
        inner_tx_header_t *txn = (inner_tx_header_t*) read_data(context, INNER_TX_HEADER_LENGTH);
        totalSize += txn->size + 2;
        // Show Transaction type
        add_new_field(context, XYM_UINT16_INNER_TRANSACTION_TYPE, STI_UINT16, sizeof(uint16_t), (uint8_t*) &txn->innerTxType);
        switch (txn->innerTxType) {
            case XYM_TXN_TRANSFER:
                parse_transfer_txn_content(context, true);
                break;
            case XYM_TXN_MOSAIC_DEFINITION:
                parse_mosaic_definition_txn_content(context, true);
                break;
            case XYM_TXN_MOSAIC_SUPPLY_CHANGE:
                parse_mosaic_supply_change_txn_content(context, true);
                break;
            case XYM_TXN_REGISTER_NAMESPACE:
                parse_namespace_registration_txn_content(context, true);
                break;
            case XYM_TXN_ADDRESS_ALIAS:
                parse_address_alias_txn_content(context, true);
                break;
            case XYM_TXN_MOSAIC_ALIAS:
                parse_mosaic_alias_txn_content(context, true);
                break;
            case XYM_TXN_HASH_LOCK:
                parse_hash_lock_txn_content(context, true);
                break;
            case XYM_TXN_MODIFY_MULTISIG_ACCOUNT:
                parse_multisig_account_modification_txn_content(context, true);
                break;
            default:
                break;
        }
        if (totalSize < len-5) {
            advance_position(context, 2);
        }
    } while (totalSize < len-5);
}

void parse_aggregate_txn_content(parse_context_t *context) {
    // get header first
    txn_fee_t *fee = (txn_fee_t*) read_data(context, sizeof(txn_fee_t));
    if (transactionContext.rawTxLength == XYM_TRANSACTION_HASH_LENGTH) {
        // Show transaction hash
        add_new_field(context, XYM_HASH256_AGG_HASH, STI_HASH256, XYM_TRANSACTION_HASH_LENGTH, context->data);
    } else {
        aggregate_txn_t *txn = (aggregate_txn_t*) read_data(context, AGGREGATE_TXN_LENGTH);
        // Show transaction hash
        add_new_field(context, XYM_HASH256_AGG_HASH, STI_HASH256, XYM_TRANSACTION_HASH_LENGTH, (uint8_t*) &txn->transactionHash);
        if (has_data(context, txn->payloadSize)) {
            parse_inner_txn_content(context, txn->payloadSize);
        } else {
            THROW(EXCEPTION_OVERFLOW);
        }
    }
    // Show max fee of aggregate tx
    add_new_field(context, XYM_UINT64_TXN_FEE, STI_XYM, sizeof(uint64_t), (uint8_t*) &fee->maxFee);
}

void parse_txn_detail(parse_context_t *context, common_header_t *txn) {
    context->result.numFields = 0;
    // Show Transaction type
    add_new_field(context, XYM_UINT16_TRANSACTION_TYPE, STI_UINT16, sizeof(uint16_t), (uint8_t*) &context->transactionType);
    switch (txn->transactionType) {
        case XYM_TXN_TRANSFER:
            parse_transfer_txn_content(context, false);
            break;
        case XYM_TXN_AGGREGATE_COMPLETE:
            parse_aggregate_txn_content(context);
            break;
        case XYM_TXN_AGGREGATE_BONDED:
            parse_aggregate_txn_content(context);
            break;
        case XYM_TXN_REGISTER_NAMESPACE:
            parse_namespace_registration_txn_content(context, false);
            break;
        case XYM_TXN_ADDRESS_ALIAS:
            parse_address_alias_txn_content(context, false);
            break;
        case XYM_TXN_MOSAIC_ALIAS:
            parse_mosaic_alias_txn_content(context, false);
            break;
        case XYM_TXN_MOSAIC_DEFINITION:
            parse_mosaic_definition_txn_content(context, false);
            break;
        case XYM_TXN_MOSAIC_SUPPLY_CHANGE:
            parse_mosaic_supply_change_txn_content(context, false);
            break;
        case XYM_TXN_MODIFY_MULTISIG_ACCOUNT:
            parse_multisig_account_modification_txn_content(context, false);
            break;
        case XYM_TXN_HASH_LOCK:
            parse_hash_lock_txn_content(context, false);
            break;
        default:
            // Mask real cause behind generic error (INCORRECT_DATA)
            THROW(0x6A80);
            break;
    }
}

void set_sign_data_length(parse_context_t *context) {
    if ((context->transactionType == XYM_TXN_AGGREGATE_COMPLETE) || (context->transactionType == XYM_TXN_AGGREGATE_BONDED)) {
        const unsigned char TESTNET_GENERATION_HASH[] = {0x6C, 0x1B, 0x92, 0x39, 0x1C, 0xCB, 0x41, 0xC9,
                                                        0x64, 0x78, 0x47, 0x1C, 0x26, 0x34, 0xC1, 0x11,
                                                        0xD9, 0xE9, 0x89, 0xDE, 0xCD, 0x66, 0x13, 0x0C,
                                                        0x04, 0x30, 0xB5, 0xB8, 0xD2, 0x01, 0x17, 0xCD};

        if (os_memcmp(TESTNET_GENERATION_HASH, context->data, XYM_TRANSACTION_HASH_LENGTH) == 0) {
            // Sign data from generation hash to transaction hash
            transactionContext.rawTxLength = 84;
        } else {
            // Sign transaction hash only
            transactionContext.rawTxLength = XYM_TRANSACTION_HASH_LENGTH;
        }
    } else {
        // Sign all data in the transaction
        transactionContext.rawTxLength = context->length;
    }
}

common_header_t *parse_txn_header(parse_context_t *context) {
    uint32_t length = sizeof(common_header_t);
    // get gen_hash and transaction_type
    common_header_t *txn = (common_header_t *) read_data(context, length);
    context->transactionType = txn->transactionType;
    return txn;
}

void parse_txn_internal(parse_context_t *context) {
    common_header_t* txn = parse_txn_header(context);
    set_sign_data_length(context);
    parse_txn_detail(context, txn);
}

void parse_txn_context(parse_context_t *context) {
    BEGIN_TRY {
        TRY {
            parse_txn_internal(context);
        }
        CATCH_OTHER(e) {
            switch (e & 0xF000u) {
                case 0x6000:
                    // Proper error, forward it further
                    THROW(e);
                default:
                    // Mask real cause behind generic error (INCORRECT_DATA)
                    THROW(0x6A80);
            }
        }
        FINALLY {
        }
    }
    END_TRY
}
