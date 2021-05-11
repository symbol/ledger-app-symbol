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
#include "get_public_key.h"
#include "apdu/global.h"
#include "xym/xym_helpers.h"
#include "ui/main/idle_menu.h"
#include "ui/address/address_ui.h"
#include "types.h"
#include "io.h"
#include "crypto.h"

static struct 
{
    size_t  keyLength;
    uint8_t key[ XYM_PUBLIC_KEY_LENGTH ];    
} G_xym_public_key;


int send_public_key()
{
    G_xym_public_key.keyLength = XYM_PUBLIC_KEY_LENGTH;    
    buffer_t buffer = { (uint8_t*) &G_xym_public_key, sizeof(G_xym_public_key), 0 };
    int      size   = io_send_response( &buffer, OK );

    return size;
}

void on_address_confirmed() 
{
    send_public_key();
    display_idle_menu();
}

void on_address_rejected() 
{
    io_send_error(ADDRESS_REJECTED);
    display_idle_menu();
}


typedef struct 
{
    bool        confirmTransaction;
    uint8_t     bip32PathLength;
    uint32_t    bip32Path[ MAX_BIP32_PATH ];
    uint8_t     networkType;
    CurveType_t curveType;
} KeyData_t;



bool extract_parameters( const uint8_t p1, const uint8_t p2, const uint8_t* data, const uint8_t dataLength, KeyData_t* keyData )
{
    // check length of data is correct
    if( dataLength != XYM_PKG_GETPUBLICKEY_LENGTH )
    {
        handle_error( INVALID_PKG_KEY_LENGTH );
        return false;
    }

    // check that p1 is set to either to confirm or not to confirm transaction by user
    if( (p1 != P1_CONFIRM) && (p1 != P1_NON_CONFIRM) )
    {
        handle_error( INVALID_P1_OR_P2 );
        return false;
    }

    // check that p2 is set to either SECP256K1 or ED25519
    if( ( ((p2 & P2_SECP256K1) == 0) && ((p2 & P2_ED25519) == 0) ) ||
        ( ((p2 & P2_SECP256K1) != 0) && ((p2 & P2_ED25519) != 0) )    )
    {
        handle_error( INVALID_P1_OR_P2 );
        return false;
    }

    // convert apdu data to bip32 path
    uint8_t bip32PathLength = crypto_get_bip32_path( data, keyData->bip32Path );
    if( 0 == bip32PathLength )
    {
        handle_error( INVALID_BIP32_PATH_LENGTH );
        return false;
    }

    // prepare output
    keyData->confirmTransaction = (p1 == P1_CONFIRM);
    keyData->bip32PathLength    = bip32PathLength;
    keyData->networkType        = data[bip32PathLength*4+1];                                   //TODO: no check is done on networkType. Are all values valid?
    keyData->curveType          = (((p2 & P2_ED25519) != 0) ? CURVE_Ed25519 : CURVE_256K1);

    return true;
}


void get_public_key( KeyData_t* keyData, uint8_t key[ XYM_PUBLIC_KEY_LENGTH ], char address[ XYM_PRETTY_ADDRESS_LENGTH+1 ] )
{
    cx_ecfp_private_key_t privateKey;

    io_seproxyhal_io_heartbeat();

    BEGIN_TRY {
        TRY 
        {            
            // get private key
            crypto_derive_private_key( keyData->bip32Path, keyData->bip32PathLength, keyData->curveType, &privateKey );

            io_seproxyhal_io_heartbeat();

            // generate public key from private key
            cx_ecfp_public_key_t  publicKey;
            cx_ecfp_generate_pair2( CX_CURVE_Ed25519, &publicKey, &privateKey, 1, CX_SHA512 );
            explicit_bzero( &privateKey, sizeof(privateKey)     );
            
            io_seproxyhal_io_heartbeat();


            xym_public_key_and_address( &publicKey,
                                         keyData->networkType,
                                         key,
                                         (char*) &address,
                                         XYM_PRETTY_ADDRESS_LENGTH + 1 );

            io_seproxyhal_io_heartbeat();

            address[XYM_PRETTY_ADDRESS_LENGTH] = '\0';
        }
        CATCH_OTHER(e) 
        {
            handle_error( e );
        }
        FINALLY 
        {
            explicit_bzero( &privateKey,    sizeof(privateKey)     );
        }
    }
    END_TRY


}

void handle_public_key( const ApduCommand_t* cmd )
{
    KeyData_t keyData;
    bool succ = extract_parameters( cmd->p1, cmd->p2, cmd->data, cmd->lc, &keyData );
    if(!succ)
    {
        return;
    }


    char address[ XYM_PRETTY_ADDRESS_LENGTH+1 ];
    get_public_key( &keyData, G_xym_public_key.key, address );


    if ( !keyData.confirmTransaction ) 
    {
        send_public_key();
        //return result;
    }
    else {
        display_address_confirmation_ui(
                address,
                on_address_confirmed,
                on_address_rejected
        );
    }
}
