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
#include "io.h"

#define PREFIX_LENGTH   4

parse_context_t parseContext;

void sign_transaction() {

    if (signState != PENDING_REVIEW) 
    {
        reset_transaction_context();
        display_idle_menu();
        return;
    }

    // Abort if we accidentally end up here again after the transaction has already been signed
    if (parseContext.data == NULL) 
    {
        display_idle_menu();
        return;
    }

    cx_ecfp_private_key_t privateKey;
    uint8_t privateKeyData[64];
    unsigned char signature[IO_APDU_BUFFER_SIZE];
    uint32_t sigLength = 0;

    io_seproxyhal_io_heartbeat();

    BEGIN_TRY {
        TRY 
        {
            if( transactionContext.curve == CURVE_Ed25519 )
            {
                os_perso_derive_node_bip32_seed_key( HDW_ED25519_SLIP10, CX_CURVE_Ed25519, transactionContext.bip32Path, transactionContext.pathLength, privateKeyData, NULL, (unsigned char*) "ed25519 seed", 12);
            }
            else
            {
                os_perso_derive_node_bip32( CX_CURVE_256K1, transactionContext.bip32Path, transactionContext.pathLength, privateKeyData, NULL );
            }

            cx_ecfp_init_private_key( CX_CURVE_Ed25519, privateKeyData, XYM_PRIVATE_KEY_LENGTH, &privateKey );
            explicit_bzero( privateKeyData, sizeof(privateKeyData) );

            io_seproxyhal_io_heartbeat();

            sigLength = (uint32_t) cx_eddsa_sign( &privateKey, CX_LAST, CX_SHA512, transactionContext.rawTx,
                                            transactionContext.rawTxLength, NULL, 0, signature,
                                            IO_APDU_BUFFER_SIZE, NULL );
        }
        CATCH_OTHER(e) 
        {
            THROW(e);
        }
        FINALLY 
        {
            explicit_bzero( privateKeyData, sizeof(privateKeyData) );
            explicit_bzero( &privateKey,    sizeof(privateKey)     );
            explicit_bzero( signature,      sizeof(signature)      );

            // Always reset transaction context after a transaction has been signed
            reset_transaction_context();
        }
    }
    END_TRY

    // send response
    buffer_t response = { signature, sigLength, 0 };
    io_send_response( &response, OK );

    // Display back the original UX
    display_idle_menu();
}

void reject_transaction() 
{
    if (signState != PENDING_REVIEW) 
    {
        reset_transaction_context();
        display_idle_menu();
        return;
    }

    // notify of rejected transaction
    handle_error( TRANSACTION_REJECTED );

    // display the idle menu
    display_idle_menu();
}

bool isFirst(uint8_t p1) 
{
	return (p1 & P1_MASK_ORDER) == 0;
}

bool hasMore(uint8_t p1) 
{
	return (p1 & P1_MASK_MORE) != 0;
}

void handle_first_packet( const ApduCommand_t* cmd ) 
{
    if( !isFirst(cmd->p1) )
    {
        handle_error( INVALID_SIGNING_PACKET_ORDER ); //THROW(0x6A80) error code is used in get_public_key to indicate an invalid key length, i added a new error code for this situation
        return;
    }

    // Reset old transaction data that might still remain
    reset_transaction_context();
    parseContext.data = transactionContext.rawTx;

    transactionContext.pathLength = cmd->data[0];
    if( (transactionContext.pathLength < 1) || (transactionContext.pathLength > MAX_BIP32_PATH) )
    {
        handle_error( INVALID_BIP32_PATH_LENGTH );
        return;
    }

    // check that p2 is set to either SECP256K1 or ED25519
    if( ( ((cmd->p2 & P2_SECP256K1) == 0) && ((cmd->p2 & P2_ED25519) == 0) ) ||
        ( ((cmd->p2 & P2_SECP256K1) != 0) && ((cmd->p2 & P2_ED25519) != 0) )    )
    {
        handle_error( INVALID_P1_OR_P2 );
        return;
    }

    // convert data to bip32 paths
    size_t dataIdx = 1;
    for( size_t i = 0; i < transactionContext.pathLength; i++, dataIdx += 4 ) 
    {
        // change endianness
        transactionContext.bip32Path[i] = (cmd->data[ dataIdx+0 ] << 24) | (cmd->data[ dataIdx+1 ] << 16) |
                                          (cmd->data[ dataIdx+2 ] <<  8) | (cmd->data[ dataIdx+3 ] <<  0);
    }


    
    transactionContext.curve = (((cmd->p2 & P2_ED25519) != 0) ? CURVE_Ed25519 : CURVE_256K1);
    handle_packet_content( cmd );
}

void handle_subsequent_packet( const ApduCommand_t* cmd ) 
{
    if (isFirst(cmd->p1)) {
        THROW( INVALID_SIGNING_PACKET_ORDER );
    }

    handle_packet_content( cmd );
}

void handle_packet_content( const ApduCommand_t* cmd ) 
{
    uint16_t totalLength = PREFIX_LENGTH + parseContext.length + cmd->lc;
    if (totalLength > MAX_RAW_TX) 
    {
        // Abort if the user is trying to sign a too large transaction
        handle_error(SIGNING_TRANSACTION_TOO_LARGE);
        return;
    }

    // Append received data to stored transaction data
    memcpy(parseContext.data + parseContext.length, cmd->data, cmd->lc);
    parseContext.length += cmd->lc;

    if( hasMore(cmd->p1) ) 
    {
        // Reply to sender with status OK
        signState = WAITING_FOR_MORE;
        io_send_response(NULL, OK);
        return;
    } 
    else
    {
        // No more data to receive, finish up and present transaction to user
        signState = PENDING_REVIEW;

        transactionContext.rawTxLength = parseContext.length;

        // Try to parse the transaction. If the parsing fails, throw an exception
        // to cause the processing to abort and the transaction context to be reset.
        switch( parse_txn_context(&parseContext) ) 
        {
            case E_TOO_MANY_FIELDS:
            {
                // Abort if there are too many fields to show on Ledger device
                handle_error( TOO_MANY_TRANSACTION_FIELDS );
                return;
            }
            case E_NOT_ENOUGH_DATA:
            case E_INVALID_DATA:
            {
                // Mask real cause behind generic error (INCORRECT_DATA)
                handle_error( TOO_MANY_TRANSACTION_FIELDS );
                return;
            }
            default:
                break;
        }

        review_transaction(&parseContext.result, sign_transaction, reject_transaction);
    }
}

void handle_sign( const ApduCommand_t* cmd ) 
{
    switch (signState) 
    {
        case IDLE:
        {
            handle_first_packet( cmd );
            break;
        }
        case WAITING_FOR_MORE:
        {
            handle_subsequent_packet( cmd );
            break;
        }
        default:
        {
            THROW(0x6A80);
        }
    }
}
