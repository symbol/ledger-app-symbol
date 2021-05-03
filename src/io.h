/*****************************************************************************
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

#pragma once
#include <string.h>
#include <stdint.h>

/**
 * Struct for buffer with size and offset. Used for sending APDU responses.
 */
typedef struct 
{
    const uint8_t *ptr;    /// Pointer to byte buffer
          size_t   size;   /// Size of byte buffer
          size_t   offset; /// Offset in byte buffer
} buffer_t;


/**
 * Must be called once, before calling any other io commands in this header
 *
 */
void io_init();


/**
 * Receive APDU command in G_io_apdu_buffer.
 *
 * @return zero or positive integer if success, -1 otherwise.
 *
 */
int io_receive_command(void);


/**
 * Send APDU response (response data + status word) by filling
 * G_io_apdu_buffer.
 *
 * @param[in] rdata
 *   Buffer with APDU response data.
 * @param[in] sw
 *   Status word of APDU response.
 *
 * @return zero or positive integer if success, -1 otherwise.
 *
 */
int io_send_response(const buffer_t *rdata, uint16_t sw);


/**
 * Send APDU response (only status word) by filling
 * G_io_apdu_buffer.
 *
 * @param[in] sw
 *   Status word of APDU response.
 *
 * @return zero or positive integer if success, -1 otherwise.
 *
 */
int io_send_error(uint16_t sw);

