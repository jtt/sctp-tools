/**
 * @file defs.h
 * @brief  File holding all system wide defines for the software.
 *
 * Copyright (c) 2008, J. Taimisto <jtaimisto@gmail.com>
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
 *     - Neither the name of the author nor the names of its
 *       contributors may be used to endorse or promote products
 *       derived from this software without specific prior written
 *       permission.  
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
 *
 */

#ifndef _DEFS_H_
#define _DEFS_H_


/*
#define DEBUG 
*/
#define ENABLE_ASSERTIONS

#define MEM_DBG_MAX_NR_ALLOC 500
#define DEBUG_MEM 
#define DEBUG_ENTER_EXIT 

#define DEBUG_DEFAULT_LEVEL 0 /* TRACE */

#define DBG_ERR_TO_STDOUT

#define DPRINT_MODULE 
#define DPRINT_STAMP

#ifdef DPRINT_MODULE

/**
 * All modules configured.  Assign the correct module to DBG_MODULE_NAME with
 * define where applicable.  Add module info to dbg_modules array in debug.c.
 * This is the index of the module info in dbg_modules
 */
enum dbg_module {
        DBG_MODULE_MEM = 0,
        DBG_MODULE_UTILS,
        DBG_MODULE_CLIENT,
        DBG_MODULE_SERVER,
        DBG_MODULE_EVENTS,
        DBG_MODULE_AUTH,
        DBG_MODULE_COMMON,
        DBG_MODULE_GENERIC /* this should always be the last */
};
#endif /* DPRINT_MODULE */
/**
 * Maximum length for interface name 
 */
#define IFNAMEMAX 20

/**
 * Don't exit if accept() returns error
 */
/*
#define IGNORE_ACCEPT_ERROR
*/

/**
 * Version number for the tools.
 */
#define TOOLS_VERSION "0.4-auth"
#ifdef FREEBSD
/* FreeBSD setsockopt() wants the protocol number as the 'level'
 * parameter, Linux uses SOL_SCTP, we'll define that here for
 * FreeBSD
 */
#define SOL_SCTP 132
#endif /* FREEBSD */

#endif /* _DEFS_H_ */
