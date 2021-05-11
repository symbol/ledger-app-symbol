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
#include "crypto.h"

#define PREFIX_LENGTH   4

buffer_t        rawTxData;  ///< transaction data is extracted from this buffer 
fields_array_t  fields;     ///< extracted data from rawTxData is used to fill this structure, which is displayed to user for confirmation

void handle_packet_content( const ApduCommand_t* cmd );


void sign_transaction()
{
    if( signState != PENDING_REVIEW ) 
    {
        reset_transaction_context();
        display_idle_menu();
        return;
    }

    // Abort if we accidentally end up here again after the transaction has already been signed
    if( rawTxData.ptr == NULL ) 
    {
        display_idle_menu();
        return;
    }

    cx_ecfp_private_key_t privateKey;
    unsigned char signature[IO_APDU_BUFFER_SIZE];
    uint32_t sigLength = 0;

    io_seproxyhal_io_heartbeat();

    BEGIN_TRY
    {
        TRY 
        {
            // get private key from bip32 path
            crypto_derive_private_key( transactionContext.bip32Path, transactionContext.pathLength, transactionContext.curve, &privateKey );
            io_seproxyhal_io_heartbeat();

            // sign transaction
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
            explicit_bzero( &privateKey, sizeof(privateKey) );
            explicit_bzero( signature,   sizeof(signature)  );

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
    // check that its the first packet
    if( !isFirst(cmd->p1) )
    {
        handle_error( INVALID_SIGNING_PACKET_ORDER );
        return;
    }

    // Reset old transaction data that might still remain
    reset_transaction_context();

    // check that p2 is set to either SECP256K1 or ED25519
    if( ( ((cmd->p2 & P2_SECP256K1) == 0) && ((cmd->p2 & P2_ED25519) == 0) ) ||
        ( ((cmd->p2 & P2_SECP256K1) != 0) && ((cmd->p2 & P2_ED25519) != 0) )    )
    {
        handle_error( INVALID_P1_OR_P2 );
        return;
    }

    // convert apdu data to bip32 path
    transactionContext.pathLength = crypto_get_bip32_path( cmd->data, transactionContext.bip32Path );
    if( 0 == transactionContext.pathLength )
    {
        handle_error( INVALID_BIP32_PATH_LENGTH );
        return;
    }
    
    transactionContext.curve = (((cmd->p2 & P2_ED25519) != 0) ? CURVE_Ed25519 : CURVE_256K1);
    handle_packet_content( cmd );
}

void handle_subsequent_packet( const ApduCommand_t* cmd ) 
{
    if (isFirst(cmd->p1)) 
    {
        THROW( INVALID_SIGNING_PACKET_ORDER );
    }

    handle_packet_content( cmd );
}

void handle_packet_content( const ApduCommand_t* cmd ) 
{
    uint16_t totalLength = PREFIX_LENGTH + transactionContext.rawTxLength + cmd->lc;
    if( totalLength > MAX_RAW_TX ) 
    {
        // Abort if the user is trying to sign a too large transaction
        handle_error(SIGNING_DATA_TOO_LARGE);
        return;
    }

    // Append received data to stored transaction data
    memcpy( transactionContext.rawTx + transactionContext.rawTxLength, cmd->data, cmd->lc );
    transactionContext.rawTxLength += cmd->lc;

    if( hasMore(cmd->p1) ) 
    {
        // Reply to sender with status OK, so that next packet is sent
        signState = WAITING_FOR_MORE;
        io_send_response(NULL, OK);
        return;
    }
    else
    {
        // No more data to receive, finish up and present transaction to user
        signState = PENDING_REVIEW;

        rawTxData.ptr    = transactionContext.rawTx;
        rawTxData.size   = transactionContext.rawTxLength;
        rawTxData.offset = 0;

        int status = parse_txn_context(&rawTxData, &fields);
        // Try to parse the transaction. If the parsing fails, throw an exception
        // to cause the processing to abort and the transaction context to be reset.
        switch( status ) 
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

        review_transaction(&fields, sign_transaction, reject_transaction);
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
            THROW(INVALID_INTERNAL_SIGNING_STATE);
        }
    }
}
