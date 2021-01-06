/*******************************************************************************
*    XYM Wallet
*    (c) 2020 Ledger
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
#include "sign_transaction.h"
#include <os.h>
#include "global.h"
#include "xym/xym_helpers.h"
#include "ui/main/idle_menu.h"
#include "transaction/transaction.h"
#include "printers.h"

#define PREFIX_LENGTH   4

parse_context_t parseContext;

void sign_transaction() {
    uint8_t privateKeyData[64];
    cx_ecfp_private_key_t privateKey;
    uint32_t tx = 0;

    if (signState != PENDING_REVIEW) {
        reset_transaction_context();
        display_idle_menu();
        return;
    }

    // Abort if we accidentally end up here again after the transaction has already been signed
    if (parseContext.data == NULL) {
        display_idle_menu();
        return;
    }

    BEGIN_TRY {
        TRY {
            io_seproxyhal_io_heartbeat();
            os_perso_derive_node_bip32(
                    CX_CURVE_256K1, transactionContext.bip32Path,
                    transactionContext.pathLength, privateKeyData, NULL);
            cx_ecfp_init_private_key(transactionContext.curve, privateKeyData, XYM_PRIVATE_KEY_LENGTH, &privateKey);
            explicit_bzero(privateKeyData, sizeof(privateKeyData));
            io_seproxyhal_io_heartbeat();
            tx = (uint32_t) cx_eddsa_sign(&privateKey, CX_LAST, CX_SHA512, transactionContext.rawTx,
                                              transactionContext.rawTxLength, NULL, 0, G_io_apdu_buffer,
                                              IO_APDU_BUFFER_SIZE, NULL);

        }
        CATCH_OTHER(e) {
            THROW(e);
        }
        FINALLY {
            explicit_bzero(privateKeyData, sizeof(privateKeyData));
            explicit_bzero(&privateKey, sizeof(privateKey));

            // Always reset transaction context after a transaction has been signed
            reset_transaction_context();
        }
    }
    END_TRY

    G_io_apdu_buffer[tx++] = 0x90;
    G_io_apdu_buffer[tx++] = 0x00;

    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);
    // Display back the original UX
    display_idle_menu();
}

void reject_transaction() {
    if (signState != PENDING_REVIEW) {
        reset_transaction_context();
        display_idle_menu();
        return;
    }

    G_io_apdu_buffer[0] = 0x69;
    G_io_apdu_buffer[1] = 0x85;

    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);

    // Reset transaction context and display back the original UX
    reset_transaction_context();
    display_idle_menu();
}

bool isFirst(uint8_t p1) {
    //return (p1 & P1_CONFIRM) == 0;
	return (p1 & P1_MASK_ORDER) == 0;
}

bool hasMore(uint8_t p1) {
    // return (p1 & P1_MORE) != 0;
	return (p1 & P1_MASK_MORE) != 0;
}

void handle_first_packet(uint8_t p1, uint8_t p2, uint8_t *workBuffer,
                       uint8_t dataLength, volatile unsigned int *flags) {
    uint32_t i;
    if (!isFirst(p1)) {
        THROW(0x6A80);
    }

    // Reset old transaction data that might still remain
    reset_transaction_context();
    parseContext.data = transactionContext.rawTx;

    transactionContext.pathLength = workBuffer[0];
    if ((transactionContext.pathLength < 0x01) ||
        (transactionContext.pathLength > MAX_BIP32_PATH)) {
        THROW(0x6a81);
    }
    workBuffer++;
    dataLength--;
    for (i = 0; i < transactionContext.pathLength; i++) {
        transactionContext.bip32Path[i] =
                (workBuffer[0] << 24u) | (workBuffer[1] << 16u) |
                (workBuffer[2] << 8u) | (workBuffer[3]);
        workBuffer += 4;
        dataLength -= 4;
    }
    if (((p2 & P2_SECP256K1) == 0) && ((p2 & P2_ED25519) == 0)) {
        THROW(0x6B00);
    }
    if (((p2 & P2_SECP256K1) != 0) && ((p2 & P2_ED25519) != 0)) {
        THROW(0x6B00);
    }
    transactionContext.curve = (((p2 & P2_ED25519) != 0) ? CX_CURVE_Ed25519 : CX_CURVE_256K1);
    handle_packet_content(p1, p2, workBuffer, dataLength, flags);
}

void handle_subsequent_packet(uint8_t p1, uint8_t p2, uint8_t *workBuffer,
                            uint8_t dataLength, volatile unsigned int *flags) {
    if (isFirst(p1)) {
        THROW(0x6A80);
    }

    handle_packet_content(p1, p2, workBuffer, dataLength, flags);
}

void handle_packet_content(uint8_t p1, uint8_t p2, uint8_t *workBuffer,
                         uint8_t dataLength, volatile unsigned int *flags) {

    uint16_t totalLength = PREFIX_LENGTH + parseContext.length + dataLength;
    if (totalLength > MAX_RAW_TX) {
        // Abort if the user is trying to sign a too large transaction
        THROW(0x6700);
    }

    // Append received data to stored transaction data
    memcpy(parseContext.data + parseContext.length, workBuffer, dataLength);
    parseContext.length += dataLength;

    if (hasMore(p1)) {
        // Reply to sender with status OK
        signState = WAITING_FOR_MORE;
        THROW(0x9000);
    } else {
        // No more data to receive, finish up and present transaction to user
        signState = PENDING_REVIEW;

        transactionContext.rawTxLength = parseContext.length;

        // Try to parse the transaction. If the parsing fails, throw an exception
        // to cause the processing to abort and the transaction context to be reset.
        switch (parse_txn_context(&parseContext)) {
            case E_TOO_MANY_FIELDS:
                // Abort if there are too many fields to show on Ledger device
                THROW(0x6700);
                break;
            case E_NOT_ENOUGH_DATA:
            case E_INVALID_DATA:
                // Mask real cause behind generic error (INCORRECT_DATA)
                THROW(0x6a80);
                break;
            default:
                break;
        }

        review_transaction(&parseContext.result, sign_transaction, reject_transaction);

        *flags |= IO_ASYNCH_REPLY;
    }
}

void handle_sign(uint8_t p1, uint8_t p2, uint8_t *workBuffer,
                uint8_t dataLength, volatile unsigned int *flags) {
    switch (signState) {
        case IDLE:
            handle_first_packet(p1, p2, workBuffer, dataLength, flags);
            break;
        case WAITING_FOR_MORE:
            handle_subsequent_packet(p1, p2, workBuffer, dataLength, flags);
            break;
        default:
            THROW(0x6A80);
    }
}
