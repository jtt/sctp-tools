/**
 * @file sctp_auth.c - Module for handling SCTP authentication.
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
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <errno.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <arpa/inet.h>
#include <sys/stat.h>

#define DBG_MODULE_NAME DBG_MODULE_AUTH
#include "defs.h"
#include "debug.h"
#include "common.h"
#include "sctp_auth.h"

/**
 * Create new authentication context for holding authentication related
 * information. 
 * @return Pointer to the created authentication context
 */
struct auth_context *auth_create_context() 
{
        struct auth_context *ret; 

        ret = mem_zalloc(sizeof(*ret));
        ret->auth_hmac_id = AUTH_DEFAULT_HMAC;
        ret->auth_chunks = 0x00;
        return ret;
}

/**
 * Delete the authentication context.
 * Deletes also all the keys stored to the context.
 * @param actx Pointer to the context to delete.
 */
void auth_delete_context(struct auth_context *actx)
{
        struct auth_keydata *key, *next_key;

        if (actx == NULL)
                return;

        key = actx->auth_keys;
        while( key != NULL) {
                next_key = key->next;
                mem_free(key);
                key = next_key;
        }

        mem_free(actx);
}

struct ident_entry {
        char *name;
        uint8_t ident;
        flags_t flag;
};

/**
 * Table for supported HMAC algorithms
 */
static struct ident_entry supported_hmac[] = {
        { "sha1", SCTP_AUTH_HMAC_ID_SHA1, 0 },
        {"sha256", SCTP_AUTH_HMAC_ID_SHA256, 0}
};

/**
 * Table for supported chunks types for which authentication 
 * can be requestes.
 */
static struct ident_entry supported_chunk[] = {
        { "data",CHUNK_TYPE_DATA, AUTH_CHUNK_DATA },
        { "sack",CHUNK_TYPE_SACK, AUTH_CHUNK_SACK },
        { "heartbeat",CHUNK_TYPE_HEARTBEAT,AUTH_CHUNK_HEARTBEAT},
        { "heartbeat-ack", CHUNK_TYPE_HEARTBEAT_ACK,AUTH_CHUNK_HEARTBEAT_ACK},
        { "abort", CHUNK_TYPE_ABORT, AUTH_CHUNK_ABORT},
        { "shutdown", CHUNK_TYPE_SHUTDOWN, AUTH_CHUNK_SHUTDOWN},
        { "error", CHUNK_TYPE_ERROR, AUTH_CHUNK_ERROR},
        { "cookie-echo", CHUNK_TYPE_COOKIE_ECHO,AUTH_CHUNK_COOKIE_ECHO},
        { "cookie-ack", CHUNK_TYPE_COOKIE_ACK,AUTH_CHUNK_COOKIE_ACK},
        { "asconf", CHUNK_TYPE_ASCONF,AUTH_CHUNK_ASCONF},
        { "asconf-ack", CHUNK_TYPE_ASCONF_ACK, AUTH_CHUNK_ASCONF_ACK},
        { "reconfig", CHUNK_TYPE_RECONFIG, AUTH_CHUNK_RECONFIG},
        { "pad", CHUNK_TYPE_PAD, AUTH_CHUNK_PAD},
        { "ftsn", CHUNK_TYPE_FTSN, AUTH_CHUNK_FTSN},
        { "pktdrop", CHUNK_TYPE_PKTDROP, AUTH_CHUNK_PKTDROP}
};


/**
 * Number of supported HMAC algorithms.
 */
#define NUM_OF_HMAC_ALG 2
/**
 * Number of supported chunks for which authentication 
 * can be turned on.
 */
#define NUM_OF_CHUNK_TYPES 15


/**
 * Parse used HMAC algorithm from given string. String should contain the name
 * of hmac algorithm to use. The parsed algorithm is set into 
 * the given authentication context.
 * @param actx Pointer to authentication context
 * @param str Pointer to string containing the algorithm name.
 * @return AUTHERR_OK if string contained name of supported algorithm, 
 * AUTHERR_UNSUPPORTED_PARAM if not. 
 */
auth_ret_t auth_parse_hmac(struct auth_context *actx, char *str)
{
        int i;

        for (i = 0; i < NUM_OF_HMAC_ALG; i++) {
                if (!strcmp(str,supported_hmac[i].name)) {
                        actx->auth_hmac_id = supported_hmac[i].ident;
                        return AUTHERR_OK;
                }
        }

        return AUTHERR_UNSUPPORTED_PARAM;
}

/**
 * Set the flag defining which chunk to authenticate according to given string.
 * The string should contain name of the chunk to authenticate, corresponding
 * flag in authentication context (actx->auth_chunks) is set
 *
 * @param actx Pointer to authentication context
 * @param str String containing name of the chunk
 * @return AUTHERR_OK if chunk was parsed and flag was set. Other error value
 * in error.
 */
auth_ret_t set_chunk_flag(struct auth_context *actx, char *str)
{
        int i;

        if (!strcmp(str,"all")) {
                        actx->auth_chunks = 0xffff;
                        return AUTHERR_OK;
        }

        for (i = 0; i < NUM_OF_CHUNK_TYPES; i++) {
                if (!strcmp(str,supported_chunk[i].name)) {
                        actx->auth_chunks = set_flag(actx->auth_chunks,
                                        supported_chunk[i].flag);
                        return AUTHERR_OK;
                }
        }
        return AUTHERR_UNSUPPORTED_PARAM;
}

/**
 * Parse chunk type for which authentication should be turned on.
 * The parsed chunk type is set into the given authentication context.
 * @param actx Pointer to the authentication context.
 * @param str String containing the name of the chunk.
 * @param AUTHERR_OK if the chunk type was parsed, AUTHERR_UNSUPPORTED_PARAM 
 * if string did not contain any supported chunk type.
 */
auth_ret_t auth_parse_chunk(struct auth_context *actx, char *str)
{
        char *tok;
        auth_ret_t ret;

        tok = strtok(str,",");
        if (!tok) 
                return set_chunk_flag(actx,str);

        while (tok) {
                if ((ret = set_chunk_flag(actx,tok)) != AUTHERR_OK)
                        return ret;

                tok = strtok(NULL,",");
        }
        return AUTHERR_OK;
}

/**
 * Separator for key id and key data
 */
#define KEY_ID_SEP ':'

/**
 * Create byte array from hexadecimal string. 
 * @param str Pointer to the string.
 * @param buf Pointer to a buffer where the data should be stored. 
 * @param buflen Length for the data buffer.
 * @return -1 if string contained illegal charactes of if the buffer did not
 * contain enough room for data.
 */
static int str_to_bytearray(const char *str, uint8_t *buf, int buflen)
{
        int len = strlen(str), blen,hi;
        const char *p;
        uint8_t *b;

        blen = len / 2;
        if (len % 2 != 0)
                blen++;

        if (buflen < blen)
                return -1;

        memset(buf,0,buflen);

        p = str; 
        b = buf;
        hi = 1;
        if (len %2 != 0) {
                /* Odd number of characters on the string, fill with zero.*/
                hi = 0;
        }

        while( *p != '\0') {
                if ( *p >= '0' && *p <= '9')
                        *b |= *p - '0';
                else if (*p >= 'a' && *p <= 'f')
                        *b |= *p - 'a' +10;
                else if ( *p >= 'A' && *p <= 'F')
                        *b |= *p - 'A' + 10;
                else
                        return -1;

                if (hi) {
                        *b = *b << 4;
                        hi = 0;
                } else {
                        b++;
                        hi = 1;
                }

                p++;
        }
        return 0;
}

/**
 * Parse an authentication key from given string. The format of the key is :
 * 
 * [<id>:][0x]<key-data>
 *
 * Where <id> is optional ID for the key (if no id is given 1 is used), if the
 * key-data is prefixed by 0x the the rest of the string is treated as the raw
 * key data bytes in hex. If no 0x is present, then the rest of the string is
 * taken as is (the trailing '\0' is not considered to be a part of the key.
 *
 * @param actx Pointer to the context where to add the key.
 * @param str Pointer to the string containing the key.
 * @return AUTHERR_OK if key was parsed succesfully, 
 * AUTHERR_INVALID_PARAM if key could not be parsed. 
 */
auth_ret_t auth_parse_key(struct auth_context *actx, char *str)
{
        struct auth_keydata *key;
        char *p;
        int len, has_id = 0;
        uint16_t id;

        p = strchr(str, KEY_ID_SEP);
        if (p != NULL) {
                /* parse the key ID first */
                *p = '\0';
                if (parse_uint16(str,&id) != 0)
                        return AUTHERR_INVALID_PARAM;
                has_id = 1;
                *p = KEY_ID_SEP;
                str = p+1;
                if (*str == '\0') 
                        return AUTHERR_INVALID_PARAM;
        }
        len = strlen(str);
        if (!len)
                return AUTHERR_INVALID_PARAM;

        key = mem_zalloc(sizeof(*key));
        if (has_id)
                key->auth_key_id = id;
        else 
                key->auth_key_id = AUTH_DEFAULT_KEY_ID;

        if (len > 2 && *str == '0' && *(str+1) == 'x') {
                str = str+2;
                len -= 2;

                if (len % 2)
                        key->auth_key_len = (len/2)+1;
                else
                        key->auth_key_len = len/2;

                key->auth_key_data = mem_alloc(key->auth_key_len);
                if (str_to_bytearray(str,key->auth_key_data,key->auth_key_len)) {
                        mem_free(key->auth_key_data);
                        mem_free(key);
                        return AUTHERR_INVALID_PARAM;
                }
        } else {
                /* just copy the raw string, NOT including the trailing '\0' */
                key->auth_key_len = len;
                key->auth_key_data = mem_alloc(key->auth_key_len);
                memcpy(key->auth_key_data, str,len);
        }
        actx->auth_keys = key;

        return AUTHERR_OK;
}

/**
 * Set the given HMAC algorithm(s) to be used. 
 * @param sock Socket for which the socket option shoud be set.
 * @param actx Pointer to the auth_context containing the HMAC parameters to set.
 * @return 0 on success, -1 if HMAC could not be set. 
 */
static int set_hmac(int sock, struct auth_context *actx)
{
        struct sctp_hmacalgo *hmac;
        int idlen = 1, struct_sz;
        int ret = 0;

        if (actx->auth_hmac_id != SCTP_AUTH_HMAC_ID_SHA1) 
                idlen = 2;

        struct_sz = sizeof(struct sctp_hmacalgo) + idlen*sizeof(uint16_t);
        hmac = mem_zalloc(struct_sz);

        /* SHA1 needs to be present always */
        if (idlen == 2) 
                hmac->shmac_idents[1] = SCTP_AUTH_HMAC_ID_SHA1;
        hmac->shmac_idents[0] = actx->auth_hmac_id;
        hmac->shmac_number_of_idents = idlen;

        TRACE("Setting %d HMAC ident(s)\n", hmac->shmac_number_of_idents);

        if (setsockopt(sock, SOL_SCTP,SCTP_HMAC_IDENT, 
                                hmac, struct_sz) != 0) {
                ERROR("Unable to set HMAC_IDENT : %s\n", strerror(errno));
                ret = -1;
        }
        mem_free(hmac);
        return ret;
}

/**
 * Set the chunks which should be authenticated.
 * @param sock Socket for which the socket option will be set.
 * @param actx Pointer to the authentication contect containing the chunks
 * requiring authentication.
 * @return 0 on success, -1 on error.
 */
static int set_chunks(int sock, struct auth_context *actx)
{
        struct sctp_authchunk chunks;
        int i;

        if (!actx->auth_chunks) 
                return 0; // no chunks defined

        for ( i = 0; i < NUM_OF_CHUNK_TYPES; i++) {
                if (is_flag(actx->auth_chunks, supported_chunk[i].flag)) {
                        memset(&chunks, 0, sizeof(chunks));
                        chunks.sauth_chunk = supported_chunk[i].ident;
                        TRACE("Adding chunk type %s(0x%.2x) to be authenticated\n",
                                        supported_chunk[i].name,
                                        chunks.sauth_chunk);
                        if (setsockopt(sock, SOL_SCTP,SCTP_AUTH_CHUNK,
                                                &chunks, sizeof(chunks)) != 0) {
                                ERROR("Unable to set AUTH_CHUNK : %s \n",
                                                strerror(errno));
                                return -1;
                        }
                }
        }
        return 0;
}

/**
 * Add a key to the set of authentication keys.
 * @param sock The socket for which the socket option will be set.
 * @param key Pointer to the key data.
 * @return 0 on success, -1 on failure.
 */
static int add_key(int sock, struct auth_keydata *key)
{
        struct sctp_authkey *sca;
        int ret = 0, struct_sz;

        struct_sz = sizeof(*sca) + key->auth_key_len * sizeof(uint8_t);
        sca = mem_zalloc(struct_sz);

        sca->sca_keynumber = key->auth_key_id;
        sca->sca_keylength = key->auth_key_len;
        memcpy(sca->sca_key, key->auth_key_data, key->auth_key_len);

        TRACE("Adding key (id:%d;len:%d bytes)\n", sca->sca_keynumber, sca->sca_keylength);
        if (setsockopt(sock, SOL_SCTP, SCTP_AUTH_KEY, sca, 
                                struct_sz) != 0) {
                ERROR("Unable to set AUTH_KEY : %s \n", strerror(errno));
                ret = -1;
        }
        return ret;
}

/**
 * Set given key as active for this and future associations.
 * The key should have been added with add_key() prior to calling this
 * function.
 * @param sock Socket for which the socket option should be set.
 * @param key Pointer to the key which should be set as active
 * @return 0 if operation succeeded, -1 if not.
 */
static int set_active_key(int sock, struct auth_keydata *key)
{
        struct sctp_authkeyid scact;
        int ret = 0;

        memset(&scact, 0, sizeof(scact));
        scact.scact_assoc_id = 0;
        scact.scact_keynumber = key->auth_key_id;

        TRACE("Setting key %d as active\n", scact.scact_keynumber);
        if (setsockopt(sock, SOL_SCTP, SCTP_AUTH_ACTIVE_KEY,
                                &scact, sizeof(scact)) != 0) {
                ERROR("Unable to set active key : %s \n", strerror(errno));
                ret = -1;
        }
        return ret;
}

/**
 * Set all the authentication parameters. 
 * @param sock Pointer to the socket for which the socket options will be set.
 * @param actx Pointer to the authentication context containing the necessary
 * parameters.
 * @return AUTHERR_OK on success, AUTHERR_INVALID_PARAM in case of failure.
 */
auth_ret_t auth_set_params(int sock, struct auth_context *actx)
{
        struct auth_keydata *key;

        if (actx->auth_hmac_id != AUTH_HMAC_NOT_SET) {
                if (set_hmac(sock, actx) != 0)
                        return AUTHERR_INVALID_PARAM;
        }

        if (set_chunks(sock,actx) != 0)
                return AUTHERR_INVALID_PARAM;

        key = actx->auth_keys;
        while (key != NULL) {
                if (add_key(sock, key) != 0)
                        return AUTHERR_INVALID_PARAM;
                key = key->next;
        }
        /* XXX - Set the first key as active */
        if (actx->auth_keys != NULL) {
                if (set_active_key(sock, actx->auth_keys) != 0) {
                        return AUTHERR_INVALID_PARAM;
                }
        }

        return AUTHERR_OK;
}

void auth_print_supported_chunks(FILE *f)
{
        int i;

        for ( i = 0; i < NUM_OF_CHUNK_TYPES; i++)
                fprintf(f,"%s ", supported_chunk[i].name);
}

#ifdef DEBUG
void debug_auth_context(struct auth_context *actx)
{
        struct auth_keydata *key;
        DBG("AUTH: hmac %d / chunks 0x%.4x\n", actx->auth_hmac_id,
                        actx->auth_chunks);
        key = actx->auth_keys;
        while (key != NULL) {
                DBG("AUTH-KEY: id %d\n",key->auth_key_id);
                DEBUG_XDUMP(key->auth_key_data, key->auth_key_len, "Key data");
                key = key->next;
        }
}
#endif /* DEBUG */
