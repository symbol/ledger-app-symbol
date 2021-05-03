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


static struct 
{
    size_t  keyLength;
    uint8_t key[ XYM_PUBLIC_KEY_LENGTH ];    
} G_xym_public_key;


int send_public_key() //TODO: Rename to send_public_key
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

    // check bip32 path lenght is correct
    uint8_t bip32PathLength = data[0];
    if( (bip32PathLength < 1) || (bip32PathLength > MAX_BIP32_PATH) )
    {
        handle_error( INVALID_BIP32_PATH_LENGTH ); //TODO: This and the above error had the same error code (0x6a80), was that intentional? I changed this one to 0x6a81
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

    // convert data to bip32 paths
    size_t dataIdx = 1;
    for( size_t pathIdx = 0; pathIdx < bip32PathLength; pathIdx++, dataIdx += 4 )  // TODO: if bip32PathLength > 5 will this not cause a buffer overflow of data[] which is a size of 22 ??
    {
        // change endianness
        keyData->bip32Path[pathIdx] = (data[dataIdx+0] << 24) | (data[ dataIdx+1 ] << 16) |
                                      (data[dataIdx+2] <<  8) | (data[ dataIdx+3 ] <<  0);
    }

    // prepare output
    keyData->confirmTransaction = (p1 == P1_CONFIRM);
    keyData->bip32PathLength    = bip32PathLength;
    keyData->networkType        = data[dataIdx];                                                  //TODO: no check is done on networkType. Are all values valid?
    keyData->curveType          = (((p2 & P2_ED25519) != 0) ? CURVE_Ed25519 : CURVE_256K1);

    return true;
}


void get_public_key( KeyData_t* keyData, uint8_t key[ XYM_PUBLIC_KEY_LENGTH ], char address[ XYM_PRETTY_ADDRESS_LENGTH+1 ] )
{
    cx_ecfp_private_key_t privateKey;
    uint8_t               privateKeyData[ XYM_PRIVATE_KEY_LENGTH ];

    io_seproxyhal_io_heartbeat();

    BEGIN_TRY {
        TRY 
        {            
            if( keyData->curveType == CURVE_Ed25519 )
            {
                os_perso_derive_node_bip32_seed_key( HDW_ED25519_SLIP10, CX_CURVE_Ed25519, keyData->bip32Path, keyData->bip32PathLength, privateKeyData, NULL, (unsigned char*) "ed25519 seed", 12 );
            }
            else 
            {
                os_perso_derive_node_bip32( CX_CURVE_256K1, keyData->bip32Path, keyData->bip32PathLength, privateKeyData, NULL );
            }

            cx_ecfp_init_private_key(CX_CURVE_Ed25519, privateKeyData, XYM_PRIVATE_KEY_LENGTH, &privateKey);
            
            io_seproxyhal_io_heartbeat();

            cx_ecfp_public_key_t  publicKey;
            cx_ecfp_generate_pair2( CX_CURVE_Ed25519, &publicKey, &privateKey, 1, CX_SHA512 );

            explicit_bzero( &privateKey,    sizeof(privateKey)     );
            explicit_bzero( privateKeyData, sizeof(privateKeyData) );
            
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
            explicit_bzero( privateKeyData, sizeof(privateKeyData) );
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
