/*****************************************************************************
 *   Ledger App Boilerplate.
 *   (c) 2020 Ledger SAS.
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
 *****************************************************************************/
#include "crypto.h"
#include "xym_helpers.h"
#include "limitations.h"



uint8_t crypto_get_bip32_path( const uint8_t* buffer, uint32_t* bip32Path )
{
    // check that bip32 path length is correct
    uint8_t bip32PathLength = buffer[0];
    if( (bip32PathLength < 1) || (bip32PathLength > MAX_BIP32_PATH) )
    {
        return 0;
    }

    // convert data to bip32 paths
    size_t dataIdx = 1;
    for( size_t pathIdx = 0; pathIdx < bip32PathLength; pathIdx++, dataIdx += 4 )  
    {
        // change endianness
        bip32Path[pathIdx] = (buffer[dataIdx+0] << 24) | 
                             (buffer[dataIdx+1] << 16) |
                             (buffer[dataIdx+2] <<  8) | 
                             (buffer[dataIdx+3] <<  0);
    }

    return bip32PathLength;
}



void crypto_derive_private_key( const uint32_t*              bip32_path,
                                const uint8_t                bip32_path_len,
                                const CurveType_t            curve_type,
                                      cx_ecfp_private_key_t* private_key    )
{
    uint8_t raw_private_key[XYM_PRIVATE_KEY_LENGTH] = {0};

    BEGIN_TRY 
    {
        TRY 
        {
            // derive the seed with bip32_path
            if( curve_type == CURVE_Ed25519 )
            {
                unsigned char seed_key[] = "ed25519 seed";

                os_perso_derive_node_bip32_seed_key( HDW_ED25519_SLIP10, 
                                                     CX_CURVE_Ed25519, 
                                                     bip32_path, 
                                                     bip32_path_len, 
                                                     raw_private_key, 
                                                     NULL, 
                                                     seed_key, 
                                                     sizeof(seed_key)-1 );
            }
            else
            {
                os_perso_derive_node_bip32( CX_CURVE_256K1,
                                            bip32_path,
                                            bip32_path_len,
                                            raw_private_key,
                                            NULL );
            }

            // initialize private_key from raw key
            cx_ecfp_init_private_key(CX_CURVE_Ed25519,
                                     raw_private_key,
                                     sizeof(raw_private_key),
                                     private_key);
        }
        CATCH_OTHER(e) 
        {
            THROW(e);
        }
        FINALLY 
        {
            explicit_bzero(&raw_private_key, sizeof(raw_private_key));
        }
    }
    END_TRY;
}
