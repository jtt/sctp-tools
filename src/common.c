/**
 * @file common.c Utilities used by both client and server.
 *
 *
 * Copyright (c) 2009 - 2010, J. Taimisto <jtaimisto@gmail.com>
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
#include <fcntl.h>
#include <unistd.h>
#include <limits.h> /* LONG_MAX, LONG_MIN */
#include <netdb.h>

#define DBG_MODULE_NAME DBG_MODULE_COMMON

#include "defs.h"
#include "debug.h"
#include "common.h"


/** 
 * @brief Reolve IP address in given string to sockaddr struture.
 *
 * The address is resolved to either AF_INET or AF_INET6 sockaddr structure.
 * AF_INET6 is tried first. The ss_family member of the @a ss parameter is set
 * to proper value if resolvation is successfull.
 * 
 * @param addr The address string.
 * @param ss Pointer to the sockaddr_storage where to save the resolved address.
 * 
 * @return -1 on error, 0 on success.
 */
int resolve( char *addr, struct sockaddr_storage *ss )
{
        struct addrinfo hints, *res = NULL;
        int rv;

        if ( addr == NULL || ss == NULL )
                return -1;

        TRACE("Resolving : %s\n", addr);

        memset( &hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_flags = AI_V4MAPPED | AI_ADDRCONFIG;

        rv = getaddrinfo( addr, NULL, &hints, &res);
        if (rv != 0 ) {
                ERROR("Unable to resolve host %s: %s\n", 
                                addr, gai_strerror(rv));
                return -1;
        }
        ASSERT( res != NULL );

        /* we'll take the first returned value, don't know
         * what would be the criteria to select the one to
         * take.
         */
        switch( res->ai_family ) {
                case AF_INET6 :
                        ASSERT( res->ai_addrlen == sizeof(struct sockaddr_in));
                        memcpy( ss, res->ai_addr, res->ai_addrlen);
                        break;
                case AF_INET :
                        ASSERT( res->ai_addrlen == sizeof(struct sockaddr_in6));
                        memcpy( ss, res->ai_addr, res->ai_addrlen);
                        break;
                default :
                        WARN("getaddrinfo() returned unknown addresstype %d \n", 
                                        res->ai_family);
                        return -1;
        }
        return 0;
}

/** 
 * @brief Parse uint16 number from given string.
 *
 * Parse unsigned 16-bit number from the given string.
 * 
 * @param str String containing the number.
 * @param dst Pointer where the parsed number should be saved.
 * 
 * @return 0 if parsing succeeded, -1 if there was error.
 */
int parse_uint16( char *str, uint16_t *dst )
{
        long ret;

        ret = strtol( str, NULL, 10 );
        if ( (ret == 0 && errno != 0 ) || 
                        (errno == ERANGE && (ret == LONG_MAX || ret == LONG_MIN ))){
                return -1;
        } else if ( ret < 0 || ret > 0xFFFF ) 
                return -1;

        *dst = (uint16_t)ret;

        return 0;
}

/** 
 * @brief Parse uint32 number from given string.
 *
 * Parse unsigned 32-bit number from the given string.
 * 
 * @param str String containing the number.
 * @param dst Pointer where the parsed number should be saved.
 * 
 * @return 0 if parsing succeeded, -1 if there was error.
 */
int parse_uint32(char *str, uint32_t *dst )
{
        long ret;

        ret = strtol( str, NULL, 10 );
        if ( (ret == 0 && errno != 0 ) || 
                        (errno == ERANGE && (ret == LONG_MAX || ret == LONG_MIN ))){
                return -1;
        } else if ( ret < 0 || ret > (long)0xFFFFFFFF )
                return -1;

        *dst = (uint32_t)ret;

        return 0;
}

/** 
 * Set the given set of flags on.
 *
 * @param flags The flags where the flags should be turned on.
 * @param set  Set of flags to turn on.
 *  
 * @return The flags with given set of flags turned on (any already turned on
 * flags are still turned on).
 */
flags_t set_flag( flags_t flags, flags_t set )
{
        return flags | set;
}

/** 
 * Check if all of the flags on given set are turned on. 
 *
 * @param flags The flags where the check should be made.
 * @param set The set of flags to set.
 * 
 * @return nonzero if the flags are turned on.
 */
int is_flag( flags_t flags, flags_t set )
{
        return (flags & set) == set;
}

/** 
 * 
 * Unset the given set of flags.
 *
 * @param flags The flags from where the given set of flgas should be turned
 * off
 * @param set  The set of flags to turn off.
 * 
 * @return Flags with the given set of flags turned on.
 */
flags_t unset_flag( flags_t flags, flags_t set )
{
        return ( flags & (~set) );
}


/** 
 * @brief Send data using SEQPKT socket. 
 *
 * The data is sent and PPID and Stream ID are set as requested.
 * 
 * @param sock The socket to use when sending.
 * @param ppid  PPID for the SCTP chunk
 * @param streamno The stream no for the stream where the data is to be written.
 * @param dst Destination host
 * @param dst_len Length of the sockaddr structure.
 * @param chunk The data to send.
 * @param chunk_size  Number of bytes to send.
 * 
 * @return Number of bytes sent on success <0 on error.
 */
int sendit( int sock, uint32_t ppid, uint16_t streamno,
                struct sockaddr *dst, size_t dst_len,
                uint8_t *chunk, int chunk_size )
{
        int ret;

        TRACE("Sending with ppid %d and stream no %d\n", ppid, streamno);

        ret = sctp_sendmsg( sock, chunk, chunk_size, 
                        dst, dst_len,
                        ppid, /* ppid */
                        0, /* flags */
                        streamno, /* stream no */
                        0, /* ttl */
                        0xF00F /* context */
                        );
        TRACE( "Sent %d / %d bytes \n", ret, chunk_size );
        return ret;
}

/** 
 * @brief Wait for incoming data and read it if it becomes available. 
 *
 * If the peer is non-null, then it is assumed that the socket is in
 * SEQPKT state.
 * 
 * @param sock Socket to use
 * @param timeout_ms Number of milliseconds to wait for incoming data.
 * @param chunk Pointer to the buffer where received data is read.
 * @param chunk_len Maximum number of bytes to read.
 * @param peer  Sockaddr where the peers address is to be set.
 * @param peerlen Size of the address structure.
 * @param info  Pointer for the structure where the additional SCTP information is to be saved.
 * @param flags Pointer where the receiving flags should be written.
 * 
 * @return  Number of bytes read on success, 0 on timeout and -1 on error, -2 if the 
 * remote end has shut down.
 */
int recv_wait( int sock, time_t timeout_ms, uint8_t *chunk, size_t chunk_len,
                struct sockaddr *peer, socklen_t *peerlen,
                struct sctp_sndrcvinfo *info, int *flags )
{
        fd_set fds;
        struct timeval tv;
        int ret;

        FD_ZERO( &fds );
        FD_SET( sock, &fds );
        memset( &tv, 0, sizeof( tv ));

        tv.tv_usec = timeout_ms * 1000;

        ret = select( sock+1, &fds, NULL, NULL, &tv );
        if ( ret < 0 ) {
                WARN("Error in select() : %s \n", strerror( errno ));
                return -1;
        } else if ( ret > 0 ) {
                if ( ! FD_ISSET( sock, &fds ) ) 
                        return -1; /* should not happen */

                ret = sctp_recvmsg( sock, chunk, chunk_len, 
                                peer, peerlen, info, flags );

                TRACE("Received %d bytes of chunk (size %d ) \n", ret, chunk_len );
                if ( ret < 0 ) {
                        if ( errno == ECONNRESET ) 
                                ret = -2;
                        else
                                ret = -1;
                } else if ( ret == 0 ){
                        ret = -2;
                }

        }

        return ret;
}
/**
 * Print error message to user.
 *
 * If DEBUG is defined use the debug macros, on non-debug, print
 * error message to stderr.
 * @param msg The message to print
 * @param num errno for the failed operation
 */
void print_error( const char *msg, int num )
{
#ifdef DEBUG
        ERROR("%s : %s\n", msg, strerror(num));
#else
        fprintf(stderr,"ERROR %s : %s \n",msg, strerror(num));
#endif /* DEBUG */
}

/**
 * Subscribe to ancillary SCTP events. 
 * @param sock The socket whose events to subscribe.
 * @return 0 if the subscription succeeded, -1 on error
 */
int subscribe_to_events( int sock ) 
{
        struct sctp_event_subscribe event;

        memset( &event, 0, sizeof( event ));
        event.sctp_data_io_event = 1;
        event.sctp_association_event = 1;
        event.sctp_shutdown_event = 1;
        event.sctp_send_failure_event = 1;

        if ( setsockopt( sock, IPPROTO_SCTP, SCTP_EVENTS,
                                &event, sizeof( event)) != 0 ) {
                fprintf(stderr, "Unable to subscribe to SCTP events: %s \n",
                                strerror( errno ));
                return -1;
        }
        return 0;
}

/**
 * Initialize the partial store context. 
 * @param store Pointer to the partial storage context.
 */
void partial_store_init( struct partial_store *store )
{
        store->partial_buf = NULL;
        store->partial_len = 0;
        store->partial_size = 0;
}
/**
 * Save data data to the partial storage. 
 *
 * @param ctx Pointer to storage context
 * @param buf Buffer containing data to store.
 * @param len Number of bytes of data. 
 * @return Total number of bytes stored to this storage.
 */
int partial_store_collect( struct partial_store *ctx, uint8_t *buf, int len)
{
        int remaining;

        if ( ctx->partial_buf == NULL ) {
                ctx->partial_size = len * 2;
                TRACE("Initial size of partial buffer is %d \n",
                                ctx->partial_size);
                ctx->partial_buf = mem_alloc( ctx->partial_size );
                ctx->partial_len = 0;
        }
        remaining = ctx->partial_size - ctx->partial_len;
        if (remaining < len ) {
                /* need to reallocate the buffer */
                ctx->partial_size = ctx->partial_size * 2;
                if (ctx->partial_size < ctx->partial_len + len)
                        ctx->partial_size = ctx->partial_len + len;

                ctx->partial_buf = mem_realloc( ctx->partial_buf, ctx->partial_size );
                TRACE("Reallocated partial buffer, length now %d \n",
                                ctx->partial_size);
        }
        /* Copy the received data to the end of the partial buffer */
        memcpy(ctx->partial_buf + ctx->partial_len,
                        buf, len );
        ctx->partial_len += len;
        return ctx->partial_len;
}

/**
 * Get the number of bytes currently stored on the partial buffer.
 * @param ctx Pointer to partial storage context.
 * @return Number of bytes of data currently stored.
 */
int partial_store_len( struct partial_store *ctx) 
{
        return ctx->partial_len;
}

/**
 * Get the pointer to data stored. 
 * The returned pointer is only valid if no partial_store_collect() is
 * called. After a call to partial_store_collect() the data pointer might
 * have been changed. 
 *
 * @param ctx Pointer to partial storage context.
 * @return Pointer to the data stored. 
 */
uint8_t *partial_store_dataptr(struct partial_store *ctx)
{
        return ctx->partial_buf;
}

/**
 * Flush the partial storage. That is reset the lenght to 0.
 *
 * @param ctx Pointer to partial storage context.
 */
void partial_store_flush(struct partial_store *ctx)
{
        ctx->partial_len = 0;
}
