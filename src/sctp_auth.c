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
