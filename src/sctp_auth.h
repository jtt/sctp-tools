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
        uint16_t auth_hmac_id; /**< HMAC algorithm used */ 
        uint8_t auth_chunk; /**< Chunk type which need to be authenticated */
        struct auth_keydata *auth_keys; /**< Linked list of shared keys */
};

/**
 * Return values for functions parsing authentication parameters from strings.
 */
enum autherr {
        AUTHERR_OK,
        AUTHERR_INVALID_PARAM, /**< Invalid, malformed parameter */
        AUTHERR_UNSUPPORTED_PARAM /**< Valid, but not supported parameter */
};

/**
 * Chunk type for data chunk, used when requesting chunks to be authenticated.
 */
#define AUTH_CHUNK_DATA 1
/**
 * Chunk type for heartbeat chunk, used when requesting chunks to be authenticated.
 */
#define AUTH_CHUNK_HEARBEAT 2

/**
 * No HMAC algorithm set, use the default one.
 */
#define AUTH_HMAC_NOT_SET 0xffff

/**
 * Default chunk type which will be authenticated if no parameter for chunk
 * type is given on command line and authentication is enabled.
 */
#define AUTH_DEFAULT_CHUNK AUTH_CHUNK_DATA
/**
 * Default HMAC algorithm for authentication if no parameter for HMAC
 * algorithm is given on command line and authentication is enabled.
 */
#define AUTH_DEFAULT_HMAC AUTH_HMAC_NOT_SET

/**
 * Default ID for a key if no key ID is given
 */
#define AUTH_DEFAULT_KEY_ID 0x01

/**
 * Check if key for authentication is given
 */
#define AUTHCTX_HAS_KEY(c)((c)->auth_keys != NULL)

/**
 * Return type for parsing functions
 */
typedef enum autherr auth_ret_t;

/* FUNCTION PROTOTYPES */

struct auth_context *auth_create_context();
void auth_delete_context(struct auth_context *actx);

auth_ret_t auth_parse_hmac(struct auth_context *actx, char *str);
auth_ret_t auth_parse_chunk(struct auth_context *actx, char *str);
auth_ret_t auth_parse_key(struct auth_context *actx, char *str);

auth_ret_t auth_set_params(int sock, struct auth_context *actx);
#ifdef DEBUG
void debug_auth_context(struct auth_context *actx);
#endif 
#endif /* _SCTP_AUTH_H_ */
