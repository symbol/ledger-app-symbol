/*******************************************************************************
*   XYM Wallet
*   (c) 2017 Ledger
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
#include "entry.h"
//#include <os.h>
#include "constants.h"
#include "global.h"
#include "messages/get_public_key.h"
#include "messages/sign_transaction.h"
#include "messages/get_app_configuration.h"

unsigned char lastINS = 0;

void handle_apdu( const ApduCommand_t* cmd ) 
{
  if ( cmd->cla != CLA)
  {
    handle_error( UNKNOWN_INSTRUCTION_CLASS );
    return;
  }

  // Reset transaction context before starting to parse a new APDU message type.
  // This helps protect against "Instruction Change" attacks
  if( cmd->ins != lastINS )
  {
    reset_transaction_context();
  }

  lastINS = cmd->ins;

  switch ( cmd->ins ) 
  {
    case GET_PUBLIC_KEY:
    {
      handle_public_key( cmd );
      break;
    }
                
    case SIGN_TX:
    {
      handle_sign( cmd );
      break;
    }
                
    case GET_VERSION:
    {
      handle_app_configuration( );
      break;
    }                
    default:
    {
      handle_error( TRANSACTION_REJECTED );
      break;
    }
  }
}
