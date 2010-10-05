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

#define DBG_MODULE_NAME DBG_MODULE_UTILS

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
        struct sockaddr_in *sin;
        struct sockaddr_in6 *sin6;
        struct hostent *hent;

        if ( addr == NULL || ss == NULL )
                return -1;

        TRACE("Resolving : %s\n", addr);

        hent = gethostbyname( addr );
        if ( hent == NULL ) 
                return -1;

        switch( hent->h_addrtype ) {

                case AF_INET6 :
                        sin6 = (struct sockaddr_in6 *)ss;
                        memcpy( &sin6->sin6_addr, hent->h_addr_list[0], sizeof(sin6->sin6_addr) );
                        ss->ss_family = AF_INET6;
                        break;
                case AF_INET :
                        sin = (struct sockaddr_in *)ss;
                        memcpy( &sin->sin_addr, hent->h_addr_list[0], sizeof(sin->sin_addr) );
                        ss->ss_family = AF_INET;
                        break;
                default :
                        WARN("gethostbyname() returned unknown addresstype %d \n", hent->h_addrtype );
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
int sendit_seq( int sock, uint16_t ppid, uint16_t streamno,
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
        if ( setsockopt( sock, IPPROTO_SCTP, SCTP_EVENTS,
                                &event, sizeof( event)) != 0 ) {
                fprintf(stderr, "Unable to subscribe to SCTP events: %s \n",
                                strerror( errno ));
                return -1;
        }
        return 0;
}
