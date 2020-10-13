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

#pragma pack(push, 1)

typedef struct {
    uint8_t recipientAddress[XYM_ADDRESS_LENGTH];
    uint16_t messageSize;
    uint8_t mosaicsCount;
    uint32_t reserved1;
    uint8_t reserved2;
} txn_header_t;

typedef struct {
    uint64_t mosaicId;
    uint64_t duration;
    uint32_t nonce;
    uint8_t flags;
    uint8_t divisibility;
} mosaic_definition_data_t;

typedef struct {
    mosaic_t mosaic;
    uint8_t action;
} mosaic_supply_change_data_t;

typedef struct {
    uint32_t size;
    uint32_t reserve1;
    uint8_t signerPublicKey[XYM_PUBLIC_KEY_LENGTH];
    uint32_t reserve2;
    uint8_t version;
    uint8_t network;
    uint16_t innerTxType;
} inner_tx_header_t;

typedef struct {
    uint8_t transactionHash[XYM_TRANSACTION_HASH_LENGTH];
    uint32_t payloadSize;
    uint32_t reserse;
} aggregate_txn_t;

typedef struct {
    uint64_t duration;
    uint64_t namespaceId;
    uint8_t registrationType;
    uint8_t nameSize;
} ns_header_t;

typedef struct {
    uint64_t namespaceId;
    uint8_t address[XYM_ADDRESS_LENGTH];
    uint8_t aliasAction;
} aa_header_t;

typedef struct {
    uint64_t namespaceId;
    uint64_t mosaicId;
    uint8_t aliasAction;
} ma_header_t;

typedef struct {
    int8_t minRemovalDelta;
    int8_t minApprovalDelta;
    uint8_t addressAdditionsCount;
    uint8_t addressDeletionsCount;
    uint32_t reserve;
} multisig_account_t;

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

#pragma pack(pop)

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

// Read data and security check
uint8_t* read_data(parse_context_t *context, uint32_t numBytes) {
    if (has_data(context, numBytes)) {
        uint32_t offset = context->offset;
        context->offset += numBytes;
        return context->data + offset;
    } else {
        THROW(EXCEPTION_OVERFLOW);
    }
}

//Move position and security check
uint8_t* move_pos(parse_context_t *context, uint32_t numBytes) {
    return read_data(context, numBytes);
}

void parse_transfer_txn_content(parse_context_t *context, bool isMultisig) {
    // get header first
    txn_fee_t *fee = NULL;
    if (!isMultisig) {
        fee = (txn_fee_t*) read_data(context, sizeof(txn_fee_t)); // Read data and security check
    }
    txn_header_t *txn = (txn_header_t*) read_data(context, sizeof(txn_header_t)); // Read data and security check
    uint32_t length = txn->mosaicsCount * sizeof(mosaic_t) + txn->messageSize;
    if (has_data(context, length)) {
        // Show Recipient address
        add_new_field(context, XYM_STR_RECIPIENT_ADDRESS, STI_ADDRESS, XYM_ADDRESS_LENGTH, (uint8_t*) txn->recipientAddress);
        // Show sent mosaic count field
        add_new_field(context, XYM_UINT8_MOSAIC_COUNT, STI_UINT8, sizeof(uint8_t), (uint8_t*) &txn->mosaicsCount);
        // Show mosaics amount
        for (uint8_t i = 0; i < txn->mosaicsCount; i++) {
            add_new_field(context, XYM_MOSAICT_AMOUNT, STI_MOSAIC_CURRENCY, sizeof(mosaic_t), read_data(context, sizeof(mosaic_t))); // Read data and security check
        }
        if (txn->messageSize == 0) {
            // Show Empty Message
            add_new_field(context, XYM_STR_TXN_MESSAGE, STI_MESSAGE, txn->messageSize, NULL);
        } else {
            // Show Message Type
            add_new_field(context, XYM_UINT8_TXN_MESSAGE_TYPE, STI_UINT8, sizeof(uint8_t), read_data(context, sizeof(uint8_t))); // Read data and security check
            // Show Message
            add_new_field(context, XYM_STR_TXN_MESSAGE, STI_MESSAGE, txn->messageSize - 1, read_data(context, txn->messageSize - 1)); // Read data and security check
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
        fee = (txn_fee_t*) read_data(context, sizeof(txn_fee_t)); // Read data and security check
    }
    mosaic_definition_data_t *txn = (mosaic_definition_data_t*) read_data(context, sizeof(mosaic_definition_data_t)); // Read data and security check
    // Show mosaic id
    add_new_field(context, XYM_UINT64_MOSAIC_ID, STI_UINT64, sizeof(uint64_t), (uint8_t*) &txn->mosaicId);
    // Show mosaic divisibility
    add_new_field(context, XYM_UINT8_MD_DIV, STI_UINT8, sizeof(uint8_t), (uint8_t*) &txn->divisibility);
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
        fee = (txn_fee_t*) read_data(context, sizeof(txn_fee_t)); // Read data and security check
    }
    mosaic_supply_change_data_t *txn = (mosaic_supply_change_data_t*) read_data(context, sizeof(mosaic_supply_change_data_t)); // Read data and security check
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
        fee = (txn_fee_t*) read_data(context, sizeof(txn_fee_t)); // Read data and security check
    }
    multisig_account_t *txn = (multisig_account_t*) read_data(context, sizeof(multisig_account_t)); // Read data and security check
    // Show address additions count
    add_new_field(context, XYM_UINT8_MAM_ADD_COUNT, STI_UINT8, sizeof(uint8_t), (uint8_t*) &txn->addressAdditionsCount);
    // Show list of addition address
    for (uint8_t i = 0; i < txn->addressAdditionsCount; i++) {
        add_new_field(context, XYM_STR_ADDRESS, STI_ADDRESS, XYM_ADDRESS_LENGTH, read_data(context, XYM_ADDRESS_LENGTH)); // Read data and security check
    }
    // Show address deletions count
    add_new_field(context, XYM_UINT8_MAM_DEL_COUNT, STI_UINT8, sizeof(uint8_t), (uint8_t*) &txn->addressDeletionsCount);
    // Show list of addition address
    for (uint8_t i = 0; i < txn->addressDeletionsCount; i++) {
        add_new_field(context, XYM_STR_ADDRESS, STI_ADDRESS, XYM_ADDRESS_LENGTH, read_data(context, XYM_ADDRESS_LENGTH)); // Read data and security check
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
        fee = (txn_fee_t*) read_data(context, sizeof(txn_fee_t)); // Read data and security check
    }
    ns_header_t *txn = (ns_header_t*) read_data(context, sizeof(ns_header_t)); // Read data and security check
    if (has_data(context, txn->nameSize)) {
        // Show namespace reg type
        add_new_field(context, XYM_UINT8_NS_REG_TYPE, STI_UINT8, sizeof(uint8_t), (uint8_t*) &txn->registrationType);
        // Show namespace/sub-namespace name
        add_new_field(context, XYM_STR_NAMESPACE, STI_STR, txn->nameSize, read_data(context, txn->nameSize)); // Read data and security check
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
        fee = (txn_fee_t*) read_data(context, sizeof(txn_fee_t)); // Read data and security check
    }
    aa_header_t *txn = (aa_header_t*) read_data(context, sizeof(aa_header_t)); // Read data and security check
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
        fee = (txn_fee_t*) read_data(context, sizeof(txn_fee_t)); // Read data and security check
    }
    ma_header_t *txn = (ma_header_t*) read_data(context, sizeof(ma_header_t)); // Read data and security check
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
        fee = (txn_fee_t*) read_data(context, sizeof(txn_fee_t)); // Read data and security check
    }
    hl_header_t *txn = (hl_header_t*) read_data(context, sizeof(hl_header_t)); // Read data and security check
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
        inner_tx_header_t *txn = (inner_tx_header_t*) read_data(context, sizeof(inner_tx_header_t)); // Read data and security check
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
            move_pos(context, 2); //Move position and security check
        }
    } while (totalSize < len-5);
}

void parse_aggregate_txn_content(parse_context_t *context) {
    // get header first
    txn_fee_t *fee = (txn_fee_t*) read_data(context, sizeof(txn_fee_t)); // Read data and security check
    if (transactionContext.rawTxLength == XYM_TRANSACTION_HASH_LENGTH) {
        // Show transaction hash
        add_new_field(context, XYM_HASH256_AGG_HASH, STI_HASH256, XYM_TRANSACTION_HASH_LENGTH, context->data);
    } else {
        aggregate_txn_t *txn = (aggregate_txn_t*) read_data(context, sizeof(aggregate_txn_t)); // Read data and security check
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
    common_header_t *txn = (common_header_t *) read_data(context, length); // Read data and security check
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
