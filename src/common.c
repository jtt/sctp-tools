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
#include "sctp_auth.h"


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
                        ASSERT( res->ai_addrlen == sizeof(struct sockaddr_in6));
                        memcpy( ss, res->ai_addr, res->ai_addrlen);
                        break;
                case AF_INET :
                        ASSERT( res->ai_addrlen == sizeof(struct sockaddr_in));
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
                        htonl(ppid), /* ppid */
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
        event.sctp_authentication_event = 1;

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
/**
 * Print the address and port from given sockaddr to stdout.
 * @param ss Pointer to sockaddr which should be printed.
 */
void print_ss( struct sockaddr_storage *ss )
{
        char peername[INET6_ADDRSTRLEN];
        uint16_t port;
        socklen_t peerlen;
        void *ptr;

        if ( ss->ss_family == AF_INET ) {
                ptr = &(((struct sockaddr_in *)ss)->sin_addr);
                port = ((struct sockaddr_in *)ss)->sin_port;
                peerlen = sizeof(struct sockaddr_in);
        } else {
                ptr = &(((struct sockaddr_in6 *)ss)->sin6_addr);
                port = ((struct sockaddr_in6 *)ss)->sin6_port;
                peerlen = sizeof(struct sockaddr_in6);
        }
        if ( inet_ntop(ss->ss_family, ptr, peername, peerlen ) != NULL ) {
                printf("%s:%d", peername, ntohs(port));
        } else {
                printf("??:%d", ntohs(port));
        }
}

/**
 * Print short information about incoming data to stdout.
 * @param from Pointer to the address of the peer.
 * @param len Number of bytes received. 
 * @param flags The flags from recvfrom() containing additional information.
 * @param info Pointer to struct sndrcvinfo, if non-NULL then also information
 * contained in this struct is printed. 
 */
void print_input( struct sockaddr_storage *from, int len, int flags, 
                struct sctp_sndrcvinfo *info)
{

        printf("< ");
        print_ss(from);
        printf(" (%d bytes) ", len);
        if ( !(flags & MSG_EOR) )
                printf("[partial]");

        printf("\n");
        if (info != NULL) {
                printf("\t stream: %d ppid: %d context: %d\n", info->sinfo_stream, 
                                info->sinfo_ppid, info->sinfo_context );
                printf("\t ssn: %d tsn: %u cumtsn: %u ", info->sinfo_ssn, 
                                info->sinfo_tsn, info->sinfo_cumtsn );
                printf("[");
                if ( info->sinfo_flags & SCTP_UNORDERED ) 
                        printf("un");
                printf("ordered]\n");
        }
}

/**
 * Print short information about outgoing data to stdout.
 * @param to Pointer to the address of the peer.
 * @param len Number of bytes sent.
 */
void print_output( struct sockaddr_storage *to, int len)
{
        printf("> ");
        print_ss(to);
        printf(" (%d bytes)", len);
        printf("\n");
}

/**
 * Print a bit more verbose information about outgoing data to stdout.
 * @param to Pointer to the address of the peer.
 * @param len Number of bytes sent.
 * @param ppid PPID set for the outgoing packet
 * @param streamno Number for the stream where the output was sent.
 */
void print_output_verbose( struct sockaddr_storage *to, int len,
                uint32_t ppid, uint16_t streamno)
{
        print_output(to,len);
        printf("\t stream: %d ppid: %d\n",
                        streamno, ppid);
}

/**
 * Parse common command line arguments.
 * @param c The command line short argument
 * @param oparg Argument for the parameter, if any
 * @param ctx Pointer to the common context which is filled according
 * to command line parameters.
 * @return 0 if argument is parsed, -1 if error occurred, -2 if 
 * command line parameter was unknown.
 */
int common_parse_args(int c, char *arg, struct common_context *ctx)
{
        auth_ret_t auth_ret;
        uint16_t streams;
#ifdef DEBUG
        uint16_t debug_level = DEBUG_DEFAULT_LEVEL;
#endif /* DEBUG */

        if (c == -1)
                return 0;

        switch(c) {
                case 'S' :
                        ctx->options = set_flag( ctx->options, SEQ_FLAG );
                        break;
                case 'e' :
                        ctx->options = set_flag( ctx->options, ECHO_FLAG );
                        break;
                case 'v' :
                        ctx->options = set_flag( ctx->options, VERBOSE_FLAG);
                        break;
                case 'x' :
                        ctx->options = set_flag(ctx->options, XDUMP_FLAG);
                        break;
                case 'I' :
                        if (parse_uint16(arg, &streams) < 0 ) {
                                fprintf(stderr,
                                        "Invalid input stream count given\n");
                                return -1;
                        }
                        if (ctx->initmsg == NULL )
                                ctx->initmsg = mem_zalloc(sizeof(struct sctp_initmsg));

                        ctx->initmsg->sinit_max_instreams = streams;
                        break;
                case 'O' :
                        if (parse_uint16(arg, &streams) < 0 ) {
                                fprintf(stderr,
                                       "Invalid output stream count given\n");
                                return -1;
                        }
                        if (ctx->initmsg == NULL)
                                ctx->initmsg = mem_zalloc(sizeof(*ctx->initmsg));

                        ctx->initmsg->sinit_num_ostreams = streams;
                        break;
#ifdef DEBUG
                case 'D' :
                        if (parse_uint16(arg, &debug_level) < 0) {
                                fprintf(stderr,"Malformed Debug level number given\n");
                                return -1;
                        }
                        if (debug_level > DBG_L_ERR) {
                                fprintf(stderr, "Invalid debug level (expected 0-3)\n");
                                return -1;
                        }
                        DBG_LEVEL(debug_level);
                        break;
#endif /* DEBUG */
                case 'A' :
                        if (ctx->actx == NULL) {
                                ctx->actx = auth_create_context();
                                ctx->options = set_flag(ctx->options, AUTH_FLAG);
                        }
                        auth_ret = auth_parse_key(ctx->actx, arg);
                        if (auth_ret == AUTHERR_INVALID_PARAM) {
                                fprintf(stderr,"Invalid key given\n");
                                return -1;
                        }
                        break;
                case 'C' :
                        if (ctx->actx == NULL) {
                                ctx->actx = auth_create_context();
                                ctx->options = set_flag(ctx->options, AUTH_FLAG);
                        }
                        auth_ret = auth_parse_chunk(ctx->actx, arg);
                        if (auth_ret == AUTHERR_INVALID_PARAM) {
                                fprintf(stderr,"Invalid chunk type given\n");
                                return -1;
                        } else if (auth_ret == AUTHERR_UNSUPPORTED_PARAM) {
                                fprintf(stderr,"Given chunk type not supported for authentication\n");
                                return -1;
                        }
                        break;
                case 'M' :
                        if (ctx->actx == NULL) {
                                ctx->actx = auth_create_context();
                                ctx->options = set_flag(ctx->options, AUTH_FLAG);
                        }
                        auth_ret = auth_parse_hmac(ctx->actx, arg);
                        if (auth_ret == AUTHERR_INVALID_PARAM) {
                                fprintf(stderr,"Invalid hmac type given\n");
                                return -1;
                        } else if (auth_ret == AUTHERR_UNSUPPORTED_PARAM) {
                                fprintf(stderr, "HMAC %s is not supported\n",
                                                arg);
                                return -1;
                        }
                        break;
                default :
                        return -2;
        }
        return 0;
}

/**
 * Print usage information about the common parameters.
 */
void common_print_usage() 
{
        printf("\t--seq          : use SOCK_SEQPACKET socket instead of SOCK_STREAM\n");
        printf("\t--echo         : Echo mode\n");
        printf("\t--verbose      : Be more verbosive \n");
        printf("\t--xdump        : Print hexdump of received data \n");
        printf("\t--instreams    : Maximum number of input streams to negotiate for the association\n");
        printf("\t--outstreams   : Number of output streams to negotiate\n");
        printf("\t--help         : Print this message \n");
        printf("\t--auth-hmac    : Select the hmac algorithm to use (sha1 or sha256)\n");
        printf("\t--auth-chunk   : Select the chunk(s) to authenticate (comma separated list of chunks)\n");
        printf("\tsupported chunks: ");
        auth_print_supported_chunks(stdout);
        printf("\n");
        printf("\t--auth-key     : Set the authentication key (format: [<id>:]0x<key-data>)\n");
        printf("\t                 The <id> is optional keyid.\n");
#ifdef DEBUG
        printf("\t--debug <level>: Set the debug level to <level> (0-3, 0=TRACE)\n");
#endif /* DEBUG */
}

/**
 * Do initialization for the common part.
 * @param ctx Pointer to the common context
 */
int common_init(struct common_context *ctx)
{
        ctx->sock = -1; 
        if ( is_flag( ctx->options, SEQ_FLAG )) {
                DBG("Using SEQPKT socket\n");
                ctx->sock = socket( PF_INET6, SOCK_SEQPACKET, IPPROTO_SCTP );
        } else {
                DBG("Using STREAM socket\n");
                ctx->sock = socket( PF_INET6, SOCK_STREAM, IPPROTO_SCTP );
        }
        if ( ctx->sock < 0 ) {
                fprintf(stderr, "Unable to create socket: %s \n",
                                strerror(errno));
                ctx->sock = -1;
                return -1;
        }
        if (ctx->initmsg != NULL ) {
                TRACE("Requesting for %d output streams and at max %d input streams\n",
                                ctx->initmsg->sinit_num_ostreams,
                                ctx->initmsg->sinit_max_instreams);
                if (setsockopt( ctx->sock, SOL_SCTP, SCTP_INITMSG, 
                                        ctx->initmsg, sizeof(*ctx->initmsg)) < 0) {
                        fprintf(stderr,"Warning: unable to set the association parameters: %s\n",
                                        strerror(errno));
                }
        }
        if (is_flag(ctx->options, AUTH_FLAG)) {
                        ASSERT(ctx->actx != NULL);
#ifdef DEBUG
                        debug_auth_context(ctx->actx);
#endif /* DEBUG */
                        if (!AUTHCTX_HAS_KEY(ctx->actx)) {
                                fprintf(stderr,"No authentication key set\n");
                                return -1;
                        }
                        if (auth_set_params(ctx->sock, ctx->actx) != AUTHERR_OK) {
                                fprintf(stderr,"Unable to set authentication parameters\n");
                                return -1;
                        }
        }
        return 0;
}

/**
 * Deinitialize the common components.
 */
void common_deinit(struct common_context *ctx)
{
        if (ctx->initmsg != NULL )
                mem_free( ctx->initmsg);
        if (ctx->actx != NULL)
                auth_delete_context(ctx->actx);

        if (ctx->sock != -1)
                close( ctx->sock );
}
