/**
 * @file sctp_client.c Simple SCTP client 
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
#include <getopt.h>

#define DBG_MODULE_NAME DBG_MODULE_CLIENT

#include "defs.h"
#include "debug.h"
#include "common.h"
#include "sctp_auth.h"

/**
 * Maximum lenght for the file where to read the data.
 */
#define FILENAME_LEN 120
/**
 * Where to read the data by default.
 */
#define DEFAULT_FILENAME "/dev/urandom"

/**
 * Default value for PPID if seqpkt socket is used.
 */
#define DEFAULT_PPID 0
/**
 * Default value for stream ID if seqpkt socket is used.
 */
#define DEFAULT_STREAM_NO 0

/**
 * Number of milliseconds to wait for reply in echo mode.
 */
#define ECHO_WAIT_MS 500
/**
 * Default size for chunk to send.
 */
#define DEFAULT_CHUNK_SIZE 120
/**
 * Default number of packets to send.
 */
#define DEFAULT_COUNT 5

/**
 * Main context for the client.
 */
struct client_ctx {
        struct sockaddr_storage host; /**< Remote host address */
        uint16_t port;/**< Port number for remote host */
        uint16_t lport; /**< Port number for local port or 0 */
        uint16_t chunk_size; /**< Number of bytes to send on each write */
        uint16_t chunk_count;/**< Number of writes to do */
        char filename[FILENAME_LEN]; /**< File to read data from */
        uint32_t ppid; /**< PPID to set to the packet. */
        uint16_t streamno; /**< Stream id to set to the packet. */
        struct common_context common; /**< Context common for client and server*/
};

/**
 * Do the client operation. 
 *
 * Send the required data and, if in echo mode, wait for reply packets.
 *
 * @param ctx Pointer to the main client context.
 * @return -1 on error, 0 on success.
 */
static int do_client( struct client_ctx *ctx )
{
        socklen_t addrlen;
        int ret,fd,i,recv_len,recv_flags;
        uint8_t *chunk;
        struct sockaddr_storage peer;
        struct sctp_sndrcvinfo info;
        socklen_t peer_len;

        if ( ctx->host.ss_family == AF_INET )
                addrlen = sizeof( struct sockaddr_in);
        else
                addrlen = sizeof( struct sockaddr_in6);

        if ( ! is_flag( ctx->common.options, SEQ_FLAG ) ) {
                ret = connect( ctx->common.sock,
                              (struct sockaddr *)&(ctx->host), addrlen );
                if ( ret < 0 ) {
                        print_error("Unable to connect()", errno);
                        return -1;
                }
        }

        TRACE("Reading data from %s \n", ctx->filename );
        fd = open( ctx->filename, O_RDONLY);
        if ( fd < 0 ) {
                WARN("Can't open file %s : %s \n",ctx->filename, strerror(errno));
                print_error("Unable to open file", errno);
                return -1;
        }

        chunk = mem_alloc( ctx->chunk_size );

        for( i = 0; i < ctx->chunk_count; i++ ) {

                ret = read( fd, chunk, ctx->chunk_size );
                if ( ret < 0 ) {
                        print_error("Unable to read data to send", errno);
                        break;
                }

                DBG("Sending %d bytes \n", ret );
                if (is_flag(ctx->common.options, XDUMP_FLAG ))
                        xdump_data( stdout, chunk, ret, "Data to send");

                printf("Sending chunk %d/%d \n", (i+1), ctx->chunk_count);

                ret = sendit( ctx->common.sock, ctx->ppid, ctx->streamno, 
                                (struct sockaddr *)&ctx->host, addrlen, 
                                chunk, ctx->chunk_size );

                if ( ret < 0 ) {
                        print_error("Unable to send data", errno);
                        break;
                }
                if (is_flag(ctx->common.options, VERBOSE_FLAG)) 
                        print_output_verbose(&ctx->host, ctx->chunk_size,
                                        ctx->ppid, ctx->streamno);


                if ( is_flag( ctx->common.options, ECHO_FLAG ) ) {
                        memset( &peer, 0, sizeof(peer));
                        memset( &info, 0, sizeof(info));
                        peer_len = addrlen;
                        recv_flags = 0;
                        recv_len = recv_wait( ctx->common.sock, 
                                        ECHO_WAIT_MS, chunk, ctx->chunk_size, 
                                        (struct sockaddr *)&peer, &peer_len,
                                        &info,&recv_flags);

                        if ( recv_len < 0 ) {
                                WARN("Error while receiving data\n");
                                print_error("Unable to read received data", errno);
                                break;
                        } else if ( recv_len == 0 ) {
                                printf("Timed out while waiting for echo\n");
                        } else {
                                if (is_flag(ctx->common.options, VERBOSE_FLAG))
                                        print_input(&peer, recv_len, recv_flags,&info);

                                printf("Received %d bytes of possible echo\n", recv_len);
                                if (is_flag(ctx->common.options, XDUMP_FLAG))
                                        xdump_data(stdout,chunk, recv_len, "Received data");
                        }
                }
        }
        close( fd );

        if ( is_flag( ctx->common.options, KEEP_FLAG ) ) {
                printf("Press any key to terminate the client ...\n");
                ret = read( 0, chunk, 1 );
                if ( ret < 0 ) {
                        WARN("read() failed : %s \n", strerror(errno));
                }
        }
        close( ctx->common.sock );
        ctx->common.sock = -1;

        return 0;
}

/**
 * Print help for command line options.
 */
static void print_usage()
{
        printf("sctp_cli v%s\n", TOOLS_VERSION);
        printf("Usage: sctp_cli [options] \n");
        printf("Available options are:\n");
        printf("\t--port <port>  : Destination port is <port> \n");
        printf("\t--lport <port> : Bind to local port <port> \n");
        printf("\t--host <host>  : Remote host to connect is <host>\n");
        printf("\t--size <size>  : Size of the chunk to send is <size>, default %d\n",
                        DEFAULT_CHUNK_SIZE);
        printf("\t--count <cnt>  : Send <cnt> chunks, default is %d\n",
                        DEFAULT_COUNT);
        printf("\t--keep         : Keep the connection after all data chunks are sent\n");
        printf("\t--file <file>  : Read data to chunks from <file>, default is %s\n",
                        DEFAULT_FILENAME);
        printf("\t--ppid <ppid>  : The PPID value for sent chunks is <ppid>, default %d\n",
                        DEFAULT_PPID);
        printf("\t--streamid <s> : Send data to stream with id <d>, default is %d\n",
                        DEFAULT_STREAM_NO);
        common_print_usage();
}

/**
 * Parse arguments and set the main context values accordingly.
 *
 * @param argc argument count.
 * @param argv arguments
 * @param ctx Pointer the the main client context.
 * @return -1 if invalid parameters were given or if mandatory parameter is
 * missing.
 */
static int parse_args( int argc, char **argv, struct client_ctx *ctx )
{
        int c, option_index,ret;
        int got_port = 0, got_addr = 0;
        struct option long_options[] = {
                { "port", 1, 0, 'p' },
                { "host", 1, 0, 'h' },
                { "size",1,0,'s' },
                { "count", 1,0,'c' },
                { "help", 0,0,'H' },
                { "keep", 0,0, 'k' },
                { "file", 1, 0, 'f' },
                { "seq", 0,0, 'S' },
                { "verbose", 0,0, 'v' },
                { "xdump",0,0,'x'},
                { "ppid", 1,0, 'P' },
                { "streamid", 1, 0, 'T' },
                { "echo", 0,0,'e' },
                { "instreams", 1,0, 'I' },
                { "outstreams", 1,0,'O' },
                { "lport",1,0,'L'},
                { "auth-key",1,0,'A'},
                { "auth-hmac",1,0,'M'},
                { "auth-chunk",1,0,'C'},
#ifdef DEBUG
                { "debug",1,0,'D'},
#endif /* DEBUG */
                { 0,0,0,0 }
        };

        while( 1 ) {

                c = getopt_long(argc, argv, "p:h:c:s:HekSvTxf:I:O:D:A:M:C:",
                                long_options, &option_index);
                if ( c == -1 ) 
                        break;

                switch ( c ) {
                        case 'h' :
                                if ( resolve( optarg, &(ctx->host) ) < 0 ) {
                                        fprintf(stderr, "Invalid IP address for host given\n");
                                        return -1;
                                }
                                got_addr = 1;
                                break;
                        case 'p' :
                                if ( parse_uint16( optarg, &(ctx->port) ) < 0 ) {
                                        fprintf(stderr, "Malformed port given\n" );
                                        return -1;
                                }
                                got_port = 1;
                                break;
                        case 'P' :
                                if ( parse_uint32( optarg, &(ctx->ppid) ) < 0 ) {
                                        fprintf(stderr, "Malformed PPID given\n" );
                                        return -1;
                                }
                                break;
                        case 'T' :
                                if ( parse_uint16( optarg, &(ctx->streamno) ) < 0 ) {
                                        fprintf(stderr, "Malformed stream number given\n" );
                                        return -1;
                                }
                                break;
                        case 'c' :
                                if ( parse_uint16( optarg, &(ctx->chunk_count) ) < 0 ) {
                                       fprintf(stderr, "Illegal chunk count given\n");
                                      return -1;
                                }
                                break;
                        case 's' :
                                if ( parse_uint16( optarg, &(ctx->chunk_size) ) < 0 ) {
                                       fprintf(stderr, "Illegal chunk count given\n");
                                      return -1;
                                }
                                break;
                        case 'k' :
                                ctx->common.options = set_flag( ctx->common.options, KEEP_FLAG );
                                break;
                        case 'f' :
                                strncpy( ctx->filename, optarg, FILENAME_LEN );
                                ctx->filename[FILENAME_LEN-1] = '\0';
                                break;
                        case 'L' :
                                if (parse_uint16(optarg, &ctx->lport) < 0) {
                                        fprintf(stderr,"Malformed local port number given\n");
                                        return -1;
                                }
                                break;
                        case 'H' :
                                print_usage();
                                return 0;
                        default :
                                ret = common_parse_args(c,optarg,&ctx->common);
                                if (ret == -1) {
                                        return ret;
                                } else if (ret == -2) {
                                        print_usage();
                                        return 0;
                                }
                                break;
                }
        }

        if ( !got_port ) {
                fprintf(stderr,"No destination port given\n");
                return -1;
        }
        if ( !got_addr ) {
                fprintf(stderr, "No destination address given\n");
                return -1;
        }

        return 1;
}

/**
 * Bind given socket to local port given as parameter. 
 *
 * @param domain PF_INET if socket is IPv4 socket, PF_INET6 if
 * the socket is IPv6.
 * @param sock socket to bind.
 * @param port Local port to bind the socket into.
 * @return 0 if the socket was bound succesfully, -1 if not.
 */
static int bind_to_local_port( int domain, int sock, uint16_t port)
{
        socklen_t salen; 
        struct sockaddr_storage ss;

        DBG("binding to local port %d\n", port);
        
        memset( &ss, 0, sizeof(ss));
        if (domain == PF_INET) {
                struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
                salen = sizeof(struct sockaddr_in);
                sin->sin_family = AF_INET;
                sin->sin_port = htons(port);
                sin->sin_addr.s_addr = htonl(INADDR_ANY);
        } else if (domain == PF_INET6) {
                struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
                salen =  sizeof(struct sockaddr_in6);
                sin6->sin6_family = AF_INET6;
                sin6->sin6_port = htons(port);
                memcpy(&sin6->sin6_addr, &in6addr_any, sizeof(in6addr_any)); 
        } else {
                WARN("Invalid domain %d\n", domain);
                return -1;
        }

        if( bind(sock, (struct sockaddr *)&ss, salen) != 0 ) {
                fprintf(stderr, "Unable to bind to local port: %s\n",
                                strerror(errno));
                return -1;
        }
        return 0;
}

int main( int argc, char *argv[] )
{
        struct client_ctx ctx;
        struct sctp_event_subscribe event;
        int ret, domain;

        memset( &ctx, 0, sizeof( ctx));

        ctx.chunk_size = DEFAULT_CHUNK_SIZE;
        ctx.chunk_count = DEFAULT_COUNT;
        ctx.streamno = DEFAULT_STREAM_NO;
        ctx.ppid = DEFAULT_PPID;
        ctx.common.sock = -1;
        strncpy( ctx.filename, DEFAULT_FILENAME, FILENAME_LEN );

        ret =  parse_args(argc, argv, &ctx );
        if ( ret < 0 ) {
                WARN("Error while parsing args\n");
                return EXIT_FAILURE;
        } else if ( ret == 0 ) {
                return EXIT_SUCCESS;
        }


        if ( ctx.host.ss_family == AF_INET ) {
                ((struct sockaddr_in *)&(ctx.host))->sin_port = htons(ctx.port);
                domain = PF_INET;
        } else {
                ((struct sockaddr_in6 *)&(ctx.host))->sin6_port = htons(ctx.port);
                domain = PF_INET6;
        }
        if (common_init(&ctx.common) != 0)
                goto out;

        if (ctx.lport != 0 ) {
                if (bind_to_local_port(domain, ctx.common.sock, ctx.lport) != 0 ) {
                        close(ctx.common.sock);
                        return EXIT_FAILURE;
                }
        }

        if (is_flag(ctx.common.options, (VERBOSE_FLAG|ECHO_FLAG))) {
                /* we need to subscribe to I/O events to be able to show them
                 * from received data
                 */
                memset(&event, 0, sizeof(event));
                event.sctp_data_io_event = 1;

                if (setsockopt(ctx.common.sock, IPPROTO_SCTP, SCTP_EVENTS,
                                        &event, sizeof(event)) != 0 ) {
                        WARN("Unable to register for SCTP IO events: %s \n",
                                        strerror(errno));
                        /* not a fatal error, we just get the I/O info wrong */
                }
        }

        do_client( &ctx );
out :
        common_deinit(&ctx.common);
        return EXIT_SUCCESS; /* XXX Error case */
}
