/*
 * @file sctp_auth.h - Type definitions for SCTP authentication module.
 *
 * Copyright (c) 2009 - 2011, J. Taimisto <jtaimisto@gmail.com>
 * All rights reserved.
 *  
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met: 
 *
 *     - Redistributions of source code must retain the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer.
 *     - Redistributions in binary form must reproduce the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer in the documentation and/or other materials
 *       provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _SCTP_AUTH_H_
#define _SCTP_AUTH_H_

/**
 * Structure holding information for one shared authentication key
 */
struct auth_keydata {
        uint16_t auth_key_id; /**< ID of the key */
        uint16_t auth_key_len; /**< Length of the keydata */
        uint8_t *auth_key_data; /**< Keydata */
        struct auth_keydata *next; /**< Next element on list */
};

/**
 * Context holding information about SCTP authentication parameters.
 */
struct auth_context {
        uint16_t *auth_hmac_ids; /**< List of supported HMACS */
        uint8_t auth_hmca_id_len; /** Number of HMAC identifiers */
        uint8_t *auth_chunks; /**< Chunk types which need to be authenticated */
        uint8_t auth_chunks_len; /**< Number of chunk types */
        struct auth_keydata *auth_keys; /**< Linked list of shared keys */
};
#endif /* _SCTP_AUTH_H_ */
