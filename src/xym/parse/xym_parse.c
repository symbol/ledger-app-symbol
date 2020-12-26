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
#include "xym/format/printers.h"

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
    uint8_t address[XYM_ADDRESS_LENGTH];
    uint64_t metadataKey;
} metadata_header_1_t;

typedef struct {
    int16_t valueSizeDelta;
    uint16_t valueSize;
} metadata_header_2_t;

typedef struct {
    metadata_header_1_t address_data;
    metadata_header_2_t value_data;
} am_header_t;

typedef struct {
    metadata_header_1_t address_data;
    uint64_t mosaicNamespaceId;
    metadata_header_2_t value_data;
} mnm_header_t;

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
    uint8_t linkedPublicKey[XYM_PUBLIC_KEY_LENGTH];
    uint8_t linkAction;
} key_link_header_t;

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
    uint8_t version;
    uint8_t networkType;
    uint16_t transactionType;
} common_header_t;

#pragma pack(pop)

#define BAIL_IF(x) {int err = x; if (err) return err;}
#define BAIL_IF_ERR(x, err) {if (x) return err;}

// Security check
static bool has_data(parse_context_t *context, uint32_t numBytes) {
    if (context->offset + numBytes < context->offset) {
        return false;
    }
    return context->offset + numBytes - 1 < context->length;
}

static field_t *get_field(parse_context_t *context, int idx) {
    return &context->result.fields[idx];
}

static int _set_field_data(field_t* field, uint8_t id, uint8_t data_type, uint32_t length, const uint8_t* data) {
    field->id = id;
    field->dataType = data_type;
    field->length = length;
    field->data = data;
    return E_SUCCESS;
}

static int set_field_data(parse_context_t *context, int idx, uint8_t id, uint8_t data_type, uint32_t length, const uint8_t* data) {
    BAIL_IF_ERR(idx >= MAX_FIELD_COUNT, E_TOO_MANY_FIELDS);
    BAIL_IF_ERR(data == NULL, E_NOT_ENOUGH_DATA);
    return _set_field_data(get_field(context, idx), id, data_type, length, data);
}

static int add_new_field(parse_context_t *context, uint8_t id, uint8_t data_type, uint32_t length, const uint8_t* data) {
    return set_field_data(context, context->result.numFields++, id, data_type, length, data);
}

// Read data and security check
static const uint8_t* read_data(parse_context_t *context, uint32_t numBytes) {
    BAIL_IF_ERR(!has_data(context, numBytes), NULL);
    uint32_t offset = context->offset;
    context->offset += numBytes;
#ifdef HAVE_PRINTF
    PRINTF("******* Read: %d bytes - Move offset: %d->%d/%d\n", numBytes, offset, context->offset, context->length);
#endif
    return context->data + offset;
}

// Move position and security check
static const uint8_t* move_pos(parse_context_t *context, uint32_t numBytes) {
    return read_data(context, numBytes); // Read data and security check
}

static int parse_transfer_txn_content(parse_context_t *context, bool isMultisig) {
    // get header first
    txn_fee_t *fee = NULL;
    if (!isMultisig) {
        fee = (txn_fee_t*) read_data(context, sizeof(txn_fee_t)); // Read data and security check
        BAIL_IF_ERR(fee == NULL, E_NOT_ENOUGH_DATA);
    }
    txn_header_t *txn = (txn_header_t*) read_data(context, sizeof(txn_header_t)); // Read data and security check
    BAIL_IF_ERR(txn == NULL, E_NOT_ENOUGH_DATA);
    uint32_t length = txn->mosaicsCount * sizeof(mosaic_t) + txn->messageSize;
    BAIL_IF_ERR(!has_data(context, length), E_INVALID_DATA);
    // Show Recipient address
    BAIL_IF(add_new_field(context, XYM_STR_RECIPIENT_ADDRESS, STI_ADDRESS, XYM_ADDRESS_LENGTH, (const uint8_t*) txn->recipientAddress));
    // Show sent mosaic count field
    BAIL_IF(add_new_field(context, XYM_UINT8_MOSAIC_COUNT, STI_UINT8, sizeof(uint8_t), (const uint8_t*) &txn->mosaicsCount));
    // Show mosaics amount
    for (uint8_t i = 0; i < txn->mosaicsCount; i++) {
        mosaic_t *mosaic = (mosaic_t*) read_data(context, sizeof(mosaic_t));
        BAIL_IF_ERR(mosaic == NULL, E_NOT_ENOUGH_DATA);
        if (mosaic->mosaicId != XYM_TESTNET_MOSAIC_ID) {
            // Unknow mosaic notification
            BAIL_IF(add_new_field(context, XYM_UNKNOWN_MOSAIC, STI_STR, 0, (const uint8_t*) mosaic));
        }
        BAIL_IF(add_new_field(context, XYM_MOSAIC_AMOUNT, STI_MOSAIC_CURRENCY, sizeof(mosaic_t), (const uint8_t*) mosaic)); // Read data and security check
    }
    if (txn->messageSize == 0) {
        // Show Empty Message
        BAIL_IF(add_new_field(context, XYM_STR_TXN_MESSAGE, STI_MESSAGE, txn->messageSize, (const uint8_t*) &txn->messageSize));
    } else {
        BAIL_IF_ERR(!has_data(context, sizeof(uint8_t)), E_INVALID_DATA);
        const uint8_t *msgType = context->data + context->offset;
        // Show Message Type
        BAIL_IF(add_new_field(context, XYM_UINT8_TXN_MESSAGE_TYPE, STI_UINT8, sizeof(uint8_t), msgType)); // Read data and security check
        if (*msgType == XYM_PERSISTENT_DELEGATED_HARVESTING) {
            // Show persistent harvesting delegation message
        #if defined(TARGET_NANOX)
            BAIL_IF(add_new_field(context, XYM_STR_TXN_HARVESTING, STI_HEX_MESSAGE, txn->messageSize, read_data(context, txn->messageSize))); // Read data and security check
        #elif defined(TARGET_NANOS)
            BAIL_IF(add_new_field(context, XYM_STR_TXN_HARVESTING_1, STI_HEX_MESSAGE, MAX_FIELD_LEN/2 - 1, read_data(context, MAX_FIELD_LEN/2 - 1))); // Read data and security check
            BAIL_IF(add_new_field(context, XYM_STR_TXN_HARVESTING_2, STI_HEX_MESSAGE, MAX_FIELD_LEN/2 - 1, read_data(context, MAX_FIELD_LEN/2 - 1))); // Read data and security check
            BAIL_IF(add_new_field(context, XYM_STR_TXN_HARVESTING_3, STI_HEX_MESSAGE, txn->messageSize - MAX_FIELD_LEN + 2, read_data(context, txn->messageSize - MAX_FIELD_LEN + 2))); // Read data and security check
        #endif
        } else {
            BAIL_IF_ERR(move_pos(context, 1) == NULL, E_NOT_ENOUGH_DATA);  // Message type
            // Show Message in plain text
            BAIL_IF(add_new_field(context, XYM_STR_TXN_MESSAGE, STI_MESSAGE, txn->messageSize - 1, read_data(context, txn->messageSize - 1))); // Read data and security check
        }
    }
    if (!isMultisig) {
        // Show fee
        BAIL_IF(add_new_field(context, XYM_UINT64_TXN_FEE, STI_XYM, sizeof(uint64_t), (const uint8_t*) &fee->maxFee));
    }
    return E_SUCCESS;
}

static int parse_mosaic_definition_txn_content(parse_context_t *context, bool isMultisig) {
    // get header first
    txn_fee_t *fee = NULL;
    if (!isMultisig) {
        fee = (txn_fee_t*) read_data(context, sizeof(txn_fee_t)); // Read data and security check
        BAIL_IF_ERR(fee == NULL, E_NOT_ENOUGH_DATA);
    }
    mosaic_definition_data_t *txn = (mosaic_definition_data_t*) read_data(context, sizeof(mosaic_definition_data_t)); // Read data and security check
    BAIL_IF_ERR(txn == NULL, E_NOT_ENOUGH_DATA);
    // Show mosaic id
    BAIL_IF(add_new_field(context, XYM_UINT64_MOSAIC_ID, STI_UINT64, sizeof(uint64_t), (const uint8_t*) &txn->mosaicId));
    // Show mosaic divisibility
    BAIL_IF(add_new_field(context, XYM_UINT8_MD_DIV, STI_UINT8, sizeof(uint8_t), (const uint8_t*) &txn->divisibility));
    // Show duration
    BAIL_IF(add_new_field(context, XYM_UINT64_DURATION, STI_UINT64, sizeof(uint64_t), (const uint8_t*) &txn->duration));
    // Show mosaic flag (Transferable)
    BAIL_IF(add_new_field(context, XYM_UINT8_MD_TRANS_FLAG, STI_UINT8, sizeof(uint8_t), (const uint8_t*) &txn->flags));
    // Show mosaic flag (Supply mutable)
    BAIL_IF(add_new_field(context, XYM_UINT8_MD_SUPPLY_FLAG, STI_UINT8, sizeof(uint8_t), (const uint8_t*) &txn->flags));
    // Show mosaic flag (Restrictable)
    BAIL_IF(add_new_field(context, XYM_UINT8_MD_RESTRICT_FLAG, STI_UINT8, sizeof(uint8_t), (const uint8_t*) &txn->flags));
    if (!isMultisig) {
        // Show fee
        BAIL_IF(add_new_field(context, XYM_UINT64_TXN_FEE, STI_XYM, sizeof(uint64_t), (const uint8_t*) &fee->maxFee));
    }
    return E_SUCCESS;
}

static int parse_mosaic_supply_change_txn_content(parse_context_t *context, bool isMultisig) {
    // get header first
    txn_fee_t *fee = NULL;
    if (!isMultisig) {
        fee = (txn_fee_t*) read_data(context, sizeof(txn_fee_t)); // Read data and security check
        BAIL_IF_ERR(fee == NULL, E_NOT_ENOUGH_DATA);
    }
    mosaic_supply_change_data_t *txn = (mosaic_supply_change_data_t*) read_data(context, sizeof(mosaic_supply_change_data_t)); // Read data and security check
    BAIL_IF_ERR(txn == NULL, E_NOT_ENOUGH_DATA);
    // Show mosaic id
    BAIL_IF(add_new_field(context, XYM_UINT64_MOSAIC_ID, STI_UINT64, sizeof(uint64_t), (const uint8_t*) &txn->mosaic.mosaicId));
    // Show supply change action
    BAIL_IF(add_new_field(context, XYM_UINT8_MSC_ACTION, STI_UINT8, sizeof(uint8_t), (const uint8_t*) &txn->action));
    // Show amount
    BAIL_IF(add_new_field(context, XYM_UINT64_MSC_AMOUNT, STI_UINT64, sizeof(mosaic_t), (const uint8_t*) &txn->mosaic.amount));
    if (!isMultisig) {
        // Show fee
        BAIL_IF(add_new_field(context, XYM_UINT64_TXN_FEE, STI_XYM, sizeof(uint64_t), (const uint8_t*) &fee->maxFee));
    }
    return E_SUCCESS;
}

static int parse_multisig_account_modification_txn_content(parse_context_t *context, bool isMultisig) {
    // get header first
    txn_fee_t *fee = NULL;
    if (!isMultisig) {
        fee = (txn_fee_t*) read_data(context, sizeof(txn_fee_t)); // Read data and security check
        BAIL_IF_ERR(fee == NULL, E_NOT_ENOUGH_DATA);
    }
    multisig_account_t *txn = (multisig_account_t*) read_data(context, sizeof(multisig_account_t)); // Read data and security check
    BAIL_IF_ERR(txn == NULL, E_NOT_ENOUGH_DATA);
    // Show address additions count
    BAIL_IF(add_new_field(context, XYM_UINT8_MAM_ADD_COUNT, STI_UINT8, sizeof(uint8_t), (const uint8_t*) &txn->addressAdditionsCount));
    // Show list of addition address
    for (uint8_t i = 0; i < txn->addressAdditionsCount; i++) {
        BAIL_IF(add_new_field(context, XYM_STR_ADDRESS, STI_ADDRESS, XYM_ADDRESS_LENGTH, read_data(context, XYM_ADDRESS_LENGTH))); // Read data and security check
    }
    // Show address deletions count
    BAIL_IF(add_new_field(context, XYM_UINT8_MAM_DEL_COUNT, STI_UINT8, sizeof(uint8_t), (const uint8_t*) &txn->addressDeletionsCount));
    // Show list of addition address
    for (uint8_t i = 0; i < txn->addressDeletionsCount; i++) {
        BAIL_IF(add_new_field(context, XYM_STR_ADDRESS, STI_ADDRESS, XYM_ADDRESS_LENGTH, read_data(context, XYM_ADDRESS_LENGTH))); // Read data and security check
    }
    // Show min approval delta
    BAIL_IF(add_new_field(context, XYM_INT8_MAM_APPROVAL_DELTA, STI_INT8, sizeof(int8_t), (const uint8_t*) &txn->minApprovalDelta));
    // Show min removal delta
    BAIL_IF(add_new_field(context, XYM_INT8_MAM_REMOVAL_DELTA, STI_INT8, sizeof(int8_t), (const uint8_t*) &txn->minRemovalDelta));
    if (!isMultisig) {
        // Show fee
        BAIL_IF(add_new_field(context, XYM_UINT64_TXN_FEE, STI_XYM, sizeof(uint64_t), (const uint8_t*) &fee->maxFee));
    }
    return E_SUCCESS;
}

static int parse_namespace_registration_txn_content(parse_context_t *context, bool isMultisig) {
    // get header first
    txn_fee_t *fee = NULL;
    if (!isMultisig) {
        fee = (txn_fee_t*) read_data(context, sizeof(txn_fee_t)); // Read data and security check
        BAIL_IF_ERR(fee == NULL, E_NOT_ENOUGH_DATA);
    }
    ns_header_t *txn = (ns_header_t*) read_data(context, sizeof(ns_header_t)); // Read data and security check
    BAIL_IF_ERR(txn == NULL, E_NOT_ENOUGH_DATA);
    // Show namespace reg type
    BAIL_IF(add_new_field(context, XYM_UINT8_NS_REG_TYPE, STI_UINT8, sizeof(uint8_t), (const uint8_t*) &txn->registrationType));
    // Show namespace/sub-namespace name
    BAIL_IF(add_new_field(context, XYM_STR_NAMESPACE, STI_STR, txn->nameSize, read_data(context, txn->nameSize))); // Read data and security check
    // Show Duration/ParentID
    BAIL_IF(add_new_field(context, txn->registrationType==0?XYM_UINT64_DURATION:XYM_UINT64_PARENTID, STI_UINT64,
        sizeof(uint64_t), (uint8_t*) &txn->duration));
    if (!isMultisig) {
        // Show fee
        BAIL_IF(add_new_field(context, XYM_UINT64_TXN_FEE, STI_XYM, sizeof(uint64_t), (const uint8_t*) &fee->maxFee));
    }
    return E_SUCCESS;
}

static int parse_account_metadata_txn_content(parse_context_t *context, bool isMultisig) {
    // get header first
    txn_fee_t *fee = NULL;
    if (!isMultisig) {
        fee = (txn_fee_t*) read_data(context, sizeof(txn_fee_t)); // Read data and security check
        BAIL_IF_ERR(fee == NULL, E_NOT_ENOUGH_DATA);
    }
    am_header_t *txn = (am_header_t*) read_data(context, sizeof(am_header_t)); // Read data and security check
    BAIL_IF_ERR(txn == NULL, E_NOT_ENOUGH_DATA);
    // Show metadata target address
    BAIL_IF(add_new_field(context, XYM_STR_METADATA_ADDRESS, STI_ADDRESS, XYM_ADDRESS_LENGTH, (const uint8_t*) &txn->address_data.address));
    // Show scope metadata key
    BAIL_IF(add_new_field(context, XYM_UINT64_METADATA_KEY, STI_UINT64, sizeof(uint64_t), (const uint8_t*) &txn->address_data.metadataKey));
    // Show different value
    BAIL_IF(add_new_field(context, XYM_STR_METADATA_VALUE, STI_MESSAGE, txn->value_data.valueSize, read_data(context, txn->value_data.valueSize))); // Read data and security check
    // Show value size delta
    BAIL_IF(add_new_field(context, XYM_INT16_VALUE_DELTA, STI_INT16, sizeof(uint16_t), (const uint8_t*) &txn->value_data.valueSizeDelta));
    if (!isMultisig) {
        // Show fee
        BAIL_IF(add_new_field(context, XYM_UINT64_TXN_FEE, STI_XYM, sizeof(uint64_t), (const uint8_t*) &fee->maxFee));
    }
    return E_SUCCESS;
}

static int parse_mosaic_namespace_metadata_txn_content(parse_context_t *context, bool isMultisig, bool isMosaicMetadata) {
    // get header first
    txn_fee_t *fee = NULL;
    if (!isMultisig) {
        fee = (txn_fee_t*) read_data(context, sizeof(txn_fee_t)); // Read data and security check
        BAIL_IF_ERR(fee == NULL, E_NOT_ENOUGH_DATA);
    }
    mnm_header_t *txn = (mnm_header_t*) read_data(context, sizeof(mnm_header_t)); // Read data and security check
    BAIL_IF_ERR(txn == NULL, E_NOT_ENOUGH_DATA);
    // Show metadata target address
    BAIL_IF(add_new_field(context, XYM_STR_METADATA_ADDRESS, STI_ADDRESS, XYM_ADDRESS_LENGTH, (const uint8_t*) &txn->address_data.address));
    // Show target mosaic/namespace id
    BAIL_IF(add_new_field(context, isMosaicMetadata ? XYM_UINT64_MOSAIC_ID : XYM_UINT64_NS_ID, STI_UINT64, sizeof(uint64_t), (const uint8_t*) &txn->mosaicNamespaceId));
    // Show scope metadata key
    BAIL_IF(add_new_field(context, XYM_UINT64_METADATA_KEY, STI_UINT64, sizeof(uint64_t), (const uint8_t*) &txn->address_data.metadataKey));
    // Show different value
    BAIL_IF(add_new_field(context, XYM_STR_METADATA_VALUE, STI_MESSAGE, txn->value_data.valueSize, read_data(context, txn->value_data.valueSize))); // Read data and security check
    // Show value size delta
    BAIL_IF(add_new_field(context, XYM_INT16_VALUE_DELTA, STI_INT16, sizeof(uint16_t), (const uint8_t*) &txn->value_data.valueSizeDelta));
    if (!isMultisig) {
        // Show fee
        BAIL_IF(add_new_field(context, XYM_UINT64_TXN_FEE, STI_XYM, sizeof(uint64_t), (const uint8_t*) &fee->maxFee));
    }
    return E_SUCCESS;
}

static int parse_address_alias_txn_content(parse_context_t *context, bool isMultisig) {
    // get header first
    txn_fee_t *fee = NULL;
    if (!isMultisig) {
        fee = (txn_fee_t*) read_data(context, sizeof(txn_fee_t)); // Read data and security check
        BAIL_IF_ERR(fee == NULL, E_NOT_ENOUGH_DATA);
    }
    aa_header_t *txn = (aa_header_t*) read_data(context, sizeof(aa_header_t)); // Read data and security check
    BAIL_IF_ERR(txn == NULL, E_NOT_ENOUGH_DATA);
    // Show alias type
    BAIL_IF(add_new_field(context, XYM_UINT8_AA_TYPE, STI_UINT8, sizeof(uint8_t), (const uint8_t*) &txn->aliasAction));
    // Show namespace id
    BAIL_IF(add_new_field(context, XYM_UINT64_NS_ID, STI_UINT64, sizeof(uint64_t), (const uint8_t*) &txn->namespaceId));
    // Show Recipient address
    BAIL_IF(add_new_field(context, XYM_STR_ADDRESS, STI_ADDRESS, XYM_ADDRESS_LENGTH, (const uint8_t*) txn->address));
    if (!isMultisig) {
        // Show fee
        BAIL_IF(add_new_field(context, XYM_UINT64_TXN_FEE, STI_XYM, sizeof(uint64_t), (const uint8_t*) &fee->maxFee));
    }
    return E_SUCCESS;
}

static int parse_mosaic_alias_txn_content(parse_context_t *context, bool isMultisig) {
    // get header first
    txn_fee_t *fee = NULL;
    if (!isMultisig) {
        fee = (txn_fee_t*) read_data(context, sizeof(txn_fee_t)); // Read data and security check
        BAIL_IF_ERR(fee == NULL, E_NOT_ENOUGH_DATA);
    }
    ma_header_t *txn = (ma_header_t*) read_data(context, sizeof(ma_header_t)); // Read data and security check
    BAIL_IF_ERR(txn == NULL, E_NOT_ENOUGH_DATA);
    // Show alisa type
    BAIL_IF(add_new_field(context, XYM_UINT8_AA_TYPE, STI_UINT8, sizeof(uint8_t), (const uint8_t*) &txn->aliasAction));
    // Show namespace id
    BAIL_IF(add_new_field(context, XYM_UINT64_NS_ID, STI_UINT64, sizeof(uint64_t), (const uint8_t*) &txn->namespaceId));
    // Show mosaic
    BAIL_IF(add_new_field(context, XYM_UINT64_MOSAIC_ID, STI_UINT64, sizeof(uint64_t), (const uint8_t*) &txn->mosaicId));
    if (!isMultisig) {
        // Show fee
        BAIL_IF(add_new_field(context, XYM_UINT64_TXN_FEE, STI_XYM, sizeof(uint64_t), (const uint8_t*) &fee->maxFee));
    }
    return E_SUCCESS;
}

static int parse_key_link_txn_content(parse_context_t *context, bool isMultisig, uint8_t tx_type) {
    // get header first
    txn_fee_t *fee = NULL;
    if (!isMultisig) {
        fee = (txn_fee_t*) read_data(context, sizeof(txn_fee_t)); // Read data and security check
        BAIL_IF_ERR(fee == NULL, E_NOT_ENOUGH_DATA);
    }
    key_link_header_t *txn = (key_link_header_t*) read_data(context, sizeof(key_link_header_t)); // Read data and security check
    BAIL_IF_ERR(txn == NULL, E_NOT_ENOUGH_DATA);
    // Show link action type
    BAIL_IF(add_new_field(context, XYM_UINT8_KL_TYPE, STI_UINT8, sizeof(uint8_t), (const uint8_t*) &txn->linkAction));
    // Show linked public key
    BAIL_IF(add_new_field(context, tx_type, STI_PUBLIC_KEY, XYM_PUBLIC_KEY_LENGTH, (const uint8_t *) &txn->linkedPublicKey));
    if (!isMultisig) {
        // Show fee
        BAIL_IF(add_new_field(context, XYM_UINT64_TXN_FEE, STI_XYM, sizeof(uint64_t), (const uint8_t*) &fee->maxFee));
    }
    BAIL_IF_ERR(move_pos(context, 7) == NULL, E_NOT_ENOUGH_DATA);  // Filling zeros
    return E_SUCCESS;
}

static int parse_hash_lock_txn_content(parse_context_t *context, bool isMultisig) {
    // get header first
    txn_fee_t *fee = NULL;
    if (!isMultisig) {
        fee = (txn_fee_t*) read_data(context, sizeof(txn_fee_t)); // Read data and security check
        BAIL_IF_ERR(fee == NULL, E_NOT_ENOUGH_DATA);
    }
    hl_header_t *txn = (hl_header_t*) read_data(context, sizeof(hl_header_t)); // Read data and security check
    BAIL_IF_ERR(txn == NULL, E_NOT_ENOUGH_DATA);
    // Show lock quantity
    BAIL_IF(add_new_field(context, XYM_MOSAIC_HL_QUANTITY, STI_MOSAIC_CURRENCY, sizeof(mosaic_t), (const uint8_t*) &txn->mosaic));
    // Show duration
    BAIL_IF(add_new_field(context, XYM_UINT64_DURATION, STI_UINT64, sizeof(uint64_t), (const uint8_t*) &txn->blockDuration));
    // Show transaction hash
    BAIL_IF(add_new_field(context, XYM_HASH256_HL_HASH, STI_HASH256, XYM_TRANSACTION_HASH_LENGTH, (const uint8_t*) &txn->aggregateBondedHash));
    if (!isMultisig) {
        // Show tx fee
        BAIL_IF(add_new_field(context, XYM_UINT64_TXN_FEE, STI_XYM, sizeof(uint64_t), (const uint8_t*) &fee->maxFee));
    }
    return E_SUCCESS;
}

static int parse_inner_txn_content(parse_context_t *context, uint32_t len, bool isCosigning) {
    uint32_t totalSize = 0;
    do {
        // get header first
        uint32_t prevOffset = context->offset;
        inner_tx_header_t *txn = (inner_tx_header_t*) read_data(context, sizeof(inner_tx_header_t)); // Read data and security check
        BAIL_IF_ERR(txn == NULL, E_NOT_ENOUGH_DATA);
        totalSize += txn->size;
        // Show Transaction type
        BAIL_IF(add_new_field(context, isCosigning ? XYM_UINT16_TRANSACTION_DETAIL_TYPE : XYM_UINT16_INNER_TRANSACTION_TYPE, STI_UINT16, sizeof(uint16_t), (const uint8_t*) &txn->innerTxType));
        switch (txn->innerTxType) {
            case XYM_TXN_TRANSFER:
                BAIL_IF(parse_transfer_txn_content(context, true));
                break;
            case XYM_TXN_MOSAIC_DEFINITION:
                BAIL_IF(parse_mosaic_definition_txn_content(context, true));
                BAIL_IF_ERR(move_pos(context, 2) == NULL, E_NOT_ENOUGH_DATA);  // Filling zeros
                break;
            case XYM_TXN_MOSAIC_SUPPLY_CHANGE:
                BAIL_IF(parse_mosaic_supply_change_txn_content(context, true));
                break;
            case XYM_TXN_MODIFY_MULTISIG_ACCOUNT:
                BAIL_IF(parse_multisig_account_modification_txn_content(context, true));
                break;
            case XYM_TXN_REGISTER_NAMESPACE:
                BAIL_IF(parse_namespace_registration_txn_content(context, true));
                break;
            case XYM_TXN_ACCOUNT_METADATA:
                BAIL_IF(parse_account_metadata_txn_content(context, true));
                break;
            case XYM_TXN_MOSAIC_METADATA:
                BAIL_IF(parse_mosaic_namespace_metadata_txn_content(context, true, true));
                break;
            case XYM_TXN_NAMESPACE_METADATA:
                BAIL_IF(parse_mosaic_namespace_metadata_txn_content(context, true, false));
                break;
            case XYM_TXN_ADDRESS_ALIAS:
                BAIL_IF(parse_address_alias_txn_content(context, true));
                break;
            case XYM_TXN_MOSAIC_ALIAS:
                BAIL_IF(parse_mosaic_alias_txn_content(context, true));
                break;
            case XYM_TXN_ACCOUNT_KEY_LINK:
                BAIL_IF(parse_key_link_txn_content(context, true, XYM_PUBLICKEY_ACCOUNT_KEY_LINK));
                break;
            case XYM_TXN_NODE_KEY_LINK:
                BAIL_IF(parse_key_link_txn_content(context, true, XYM_PUBLICKEY_NODE_KEY_LINK));
                break;
            case XYM_TXN_VRF_KEY_LINK:
                BAIL_IF(parse_key_link_txn_content(context, true, XYM_PUBLICKEY_VRF_KEY_LINK));
                break;
            case XYM_TXN_HASH_LOCK:
                BAIL_IF(parse_hash_lock_txn_content(context, true));
                break;
            default:
                return E_INVALID_DATA;
        }
        uint32_t processedDataLength = context->offset - prevOffset;
        if (txn->size > processedDataLength) {
            BAIL_IF_ERR(move_pos(context, txn->size - processedDataLength) == NULL, E_NOT_ENOUGH_DATA);  // Move position and security check
        } else {
            totalSize = totalSize + (processedDataLength - txn->size);
        }
    } while (totalSize < len - sizeof(inner_tx_header_t));
    return E_SUCCESS;
}

static int parse_aggregate_txn_content(parse_context_t *context) {
    // get header first
    txn_fee_t *fee = (txn_fee_t*) read_data(context, sizeof(txn_fee_t)); // Read data and security check
    BAIL_IF_ERR(fee == NULL, E_NOT_ENOUGH_DATA);
    aggregate_txn_t *txn = (aggregate_txn_t*) read_data(context, sizeof(aggregate_txn_t)); // Read data and security check
    BAIL_IF_ERR(txn == NULL, E_NOT_ENOUGH_DATA);
    bool isCosigning = transactionContext.rawTxLength == XYM_TRANSACTION_HASH_LENGTH;
    const uint8_t* p_tx_hash = isCosigning ? context-> data : txn->transactionHash;
    // Show transaction hash
    BAIL_IF(add_new_field(context, XYM_HASH256_AGG_HASH, STI_HASH256, XYM_TRANSACTION_HASH_LENGTH, p_tx_hash));
    BAIL_IF_ERR(!has_data(context, txn->payloadSize), E_INVALID_DATA);
    BAIL_IF(parse_inner_txn_content(context, txn->payloadSize, isCosigning));
    // Show max fee of aggregate tx
    BAIL_IF(add_new_field(context, XYM_UINT64_TXN_FEE, STI_XYM, sizeof(uint64_t), (const uint8_t*) &fee->maxFee));
    return E_SUCCESS;
}

static int parse_txn_detail(parse_context_t *context, common_header_t *txn) {
    int result;
    context->result.numFields = 0;
    // Show Transaction type
    BAIL_IF(add_new_field(context, XYM_UINT16_TRANSACTION_TYPE, STI_UINT16, sizeof(uint16_t), (const uint8_t*) &context->transactionType));
    switch (txn->transactionType) {
        case XYM_TXN_TRANSFER:
            result = parse_transfer_txn_content(context, false);
            break;
        case XYM_TXN_AGGREGATE_COMPLETE:
            result = parse_aggregate_txn_content(context);
            break;
        case XYM_TXN_AGGREGATE_BONDED:
            result = parse_aggregate_txn_content(context);
            break;
        case XYM_TXN_MODIFY_MULTISIG_ACCOUNT:
            result = parse_multisig_account_modification_txn_content(context, false);
            break;
        case XYM_TXN_REGISTER_NAMESPACE:
            result = parse_namespace_registration_txn_content(context, false);
            break;
        case XYM_TXN_ADDRESS_ALIAS:
            result = parse_address_alias_txn_content(context, false);
            break;
        case XYM_TXN_MOSAIC_ALIAS:
            result = parse_mosaic_alias_txn_content(context, false);
            break;
        case XYM_TXN_MOSAIC_DEFINITION:
            result = parse_mosaic_definition_txn_content(context, false);
            break;
        case XYM_TXN_MOSAIC_SUPPLY_CHANGE:
            result = parse_mosaic_supply_change_txn_content(context, false);
            break;
        case XYM_TXN_HASH_LOCK:
            result = parse_hash_lock_txn_content(context, false);
            break;
        default:
            result = E_INVALID_DATA;
            break;
    }
    return result;
}

static void set_sign_data_length(parse_context_t *context) {
    if ((context->transactionType == XYM_TXN_AGGREGATE_COMPLETE) || (context->transactionType == XYM_TXN_AGGREGATE_BONDED)) {
        const unsigned char TESTNET_GENERATION_HASH[] = {0x6C, 0x1B, 0x92, 0x39, 0x1C, 0xCB, 0x41, 0xC9,
                                                        0x64, 0x78, 0x47, 0x1C, 0x26, 0x34, 0xC1, 0x11,
                                                        0xD9, 0xE9, 0x89, 0xDE, 0xCD, 0x66, 0x13, 0x0C,
                                                        0x04, 0x30, 0xB5, 0xB8, 0xD2, 0x01, 0x17, 0xCD};

        if (memcmp(TESTNET_GENERATION_HASH, context->data, XYM_TRANSACTION_HASH_LENGTH) == 0) {
            // Sign data from generation hash to transaction hash
            // XYM_AGGREGATE_SIGNING_LENGTH = XYM_TRANSACTION_HASH_LENGTH
            //                                + sizeof(common_header_t) + sizeof(txn_fee_t) = 84
            transactionContext.rawTxLength = XYM_AGGREGATE_SIGNING_LENGTH;
        } else {
            // Sign transaction hash only (multisig cosigning transaction)
            transactionContext.rawTxLength = XYM_TRANSACTION_HASH_LENGTH;
        }
    } else {
        // Sign all data in the transaction
        transactionContext.rawTxLength = context->length;
    }
}

static common_header_t *parse_txn_header(parse_context_t *context) {
    // get gen_hash and transaction_type
    common_header_t *txn = (common_header_t *) read_data(context, sizeof(common_header_t)); // Read data and security check
    BAIL_IF_ERR(txn == NULL, NULL);
    context->transactionType = txn->transactionType;
    return txn;
}

int parse_txn_context(parse_context_t *context) {
    common_header_t* txn = parse_txn_header(context);
    BAIL_IF_ERR(txn == NULL, E_NOT_ENOUGH_DATA);
    set_sign_data_length(context);
    return parse_txn_detail(context, txn);
}
