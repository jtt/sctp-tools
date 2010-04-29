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

#include "defs.h"
#include "debug.h"
#include "common.h"


#define PROG_VERSION "0.0.2"

/**
 * Flag indicating that we should keep the connection after
 * all data is sent.
 */
#define KEEP_FLAG 0x01
/**
 * Flag indicating verbose mode. 
 */
#define VERBOSE_FLAG 0x01 << 1
/**
 * Flag indicating the SOCK_SEQPACKET should be used. 
 */
#define SEQ_FLAG 0x01 << 2

#define ECHO_FLAG 0x01 << 3

#define FILENAME_LEN 120
#define DEFAULT_FILENAME "/dev/urandom"

#define DEFAULT_PPID 0
#define DEFAULT_STREAM_NO 0

#define ECHO_WAIT_MS 500



struct client_ctx {
        int sock; /**< Socket to use for sending */
        struct sockaddr_storage host; /**< Remote host address */
        uint16_t port;/**< Port number for remote host */
        uint16_t chunk_size; /**< Number of bytes to send on each write */
        uint16_t chunk_count;/**< Number of writes to do */
        flags_t options; /**< Runtime options */
        char filename[FILENAME_LEN]; /**< File to read data from */
        uint16_t ppid;
        uint16_t streamno;
};


#define DEFAULT_CHUNK_SIZE 120
#define DEFAULT_COUNT 5

static int do_client( struct client_ctx *ctx )
{
        socklen_t addrlen;
        int ret,fd,i,recv_len;
        uint8_t *chunk;
        struct sockaddr_storage peer;
        socklen_t peer_len;

        if ( ctx->host.ss_family == AF_INET )
                addrlen = sizeof( struct sockaddr_in);
        else
                addrlen = sizeof( struct sockaddr_in6);

        if ( ! is_flag( ctx->options, SEQ_FLAG ) ) {
                ret = connect( ctx->sock, (struct sockaddr *)&(ctx->host), addrlen );
                if ( ret < 0 ) {
                        WARN("Connect() failed: %s \n", strerror(errno));
                        return -1;
                }
        }

        TRACE("Reading data from %s \n", ctx->filename );
        fd = open( ctx->filename, O_RDONLY);
        if ( fd < 0 ) {
                WARN("Can't open file %s : %s \n",ctx->filename, strerror(errno));
                return -1;
        }

        chunk = mem_alloc( ctx->chunk_size );

        for( i = 0; i < ctx->chunk_count; i++ ) {

                ret = read( fd, chunk, ctx->chunk_size );
                if ( ret < 0 ) {
                        WARN(" read() failed: %s \n", strerror(errno));
                }

                DBG("Sending %d bytes \n", ret );
                if ( is_flag( ctx->options, VERBOSE_FLAG ) ) {
                        xdump_data( stdout, chunk, ret, "Data to send");
                }

                if ( is_flag( ctx->options, SEQ_FLAG ) )
                        ret = sendit_seq( ctx->sock, ctx->ppid, ctx->streamno, 
                                        (struct sockaddr *)&ctx->host, addrlen, 
                                        chunk, ctx->chunk_size );
                else
                        ret = send( ctx->sock, chunk, ret, 0 );

                if ( ret < 0 ) {
                        WARN("send() failed: %s \n", strerror(errno));
                }
                if ( is_flag( ctx->options, ECHO_FLAG ) ) {
                        if ( is_flag( ctx->options, SEQ_FLAG )) {
                                        memset( &peer, 0, sizeof( peer ));
                                        peer_len = addrlen;

                                        recv_len = recv_wait( ctx->sock, 
                                                ECHO_WAIT_MS, chunk, ctx->chunk_size, 
                                                (struct sockaddr *)&peer, &peer_len,
                                                NULL );
                        } else {
                                        recv_len = recv_wait( ctx->sock, 
                                                ECHO_WAIT_MS, chunk, ctx->chunk_size, 
                                                NULL, NULL, NULL );
                        }
                        if ( recv_len < 0 ) {
                                WARN("Error while receiving data\n");
                        } else if ( recv_len == 0 ) {
                                WARN("Timed out while waiting for echo\n");
                        } else {
                                printf("Received %d bytes of possible echo\n", recv_len);
                        }
                }
        }
        close( fd );

        if ( is_flag( ctx->options, KEEP_FLAG ) ) {
                printf("Press any key to terminate the client ...\n");
                ret = read( 0, chunk, 1 );
                if ( ret < 0 ) {
                        WARN("read() failed : %s \n", strerror(errno));
                }
        }


        close( ctx->sock );

        return 0;
}

static void print_usage()
{
        printf("sctp_cli v%s\n", PROG_VERSION);
        printf("Usage: sctp_cli [options] \n");
        printf("Available options are:\n");
        printf("\t--port <port>     : Destination port is <port> \n");
        printf("\t--host <host>     : Remote host to connect is <host>\n");
        printf("\t--size <size>     : Size of the chunk to send is <size>, default %d\n",
                        DEFAULT_CHUNK_SIZE);
        printf("\t--count <cnt>     : Send <cnt> chunks, default is %d\n",
                        DEFAULT_COUNT);
        printf("\t--keep            : Keep the connection after all data chunks are sent\n");
        printf("\t--file <file>     : Read data to chunks from <file>, default is %s\n",
                        DEFAULT_FILENAME);
        printf("\t--seq             : Use SOCK_SEQPACKET instead of SOCK_STREAM \n");
        printf("\t--verbose         : Be more verbosive\n");
        printf("\t--ppid <ppid>     : The PPID value for sent chunks is <ppid>, default %d\n",
                        DEFAULT_PPID);
        printf("\t--streamid <s>    : Send data to stream with id <d>, default is %d\n",
                        DEFAULT_STREAM_NO);
        printf("\t--echo            : Expect the server to echo sent data back\n");
        printf("\t--help            : Print this message \n");
}

static int parse_args( int argc, char **argv, struct client_ctx *ctx )
{
        int c, option_index;
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
                { "ppid", 1,0, 'P' },
                { "streamid", 1, 0, 'T' },
                { "echo", 0,0,'e' },
                { 0,0,0,0 }
        };

        while( 1 ) {

                c = getopt_long(argc, argv, "p:h:c:s:Hef:", long_options, &option_index);
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
                        case 'S' :
                                ctx->options = set_flag( ctx->options, SEQ_FLAG );
                                break;
                        case 'e' :
                                ctx->options = set_flag( ctx->options, ECHO_FLAG );
                                break;
                        case 'P' :
                                if ( parse_uint16( optarg, &(ctx->ppid) ) < 0 ) {
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
                                ctx->options = set_flag( ctx->options, KEEP_FLAG );
                                break;
                        case 'f' :
                                strncpy( ctx->filename, optarg, FILENAME_LEN );
                                ctx->filename[FILENAME_LEN-1] = '\0';
                                break;
                        case 'v' :
                                ctx->options = set_flag( ctx->options, VERBOSE_FLAG);
                                break;
                        case 'H' :
                        default :
                                print_usage();
                                return 0;
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



int main( int argc, char *argv[] )
{
        struct client_ctx ctx;
        int ret, domain, type;

        memset( &ctx, 0, sizeof( ctx));

        ctx.chunk_size = DEFAULT_CHUNK_SIZE;
        ctx.chunk_count = DEFAULT_COUNT;
        ctx.streamno = DEFAULT_STREAM_NO;
        ctx.ppid = DEFAULT_PPID;
        strncpy( ctx.filename, DEFAULT_FILENAME, FILENAME_LEN );

        ret =  parse_args(argc, argv, &ctx );
        if ( ret < 0 ) {
                WARN("Error while parsing args\n");
                return EXIT_FAILURE;
        } else if ( ret == 0 ) {
                return EXIT_SUCCESS;
        }

        if (( ctx.ppid != DEFAULT_PPID || ctx.streamno != DEFAULT_STREAM_NO )
                        && ! is_flag( ctx.options, SEQ_FLAG ) ) {
                printf("Warning: ppid and/or stream number options are ignored for SOCK_STREAM socket\n");
        }


        if ( ctx.host.ss_family == AF_INET ) {
                ((struct sockaddr_in *)&(ctx.host))->sin_port = htons(ctx.port);
                domain = PF_INET;
        } else {
                ((struct sockaddr_in6 *)&(ctx.host))->sin6_port = htons(ctx.port);
                domain = PF_INET6;
        }

        if ( is_flag( ctx.options, SEQ_FLAG ) ) {
                DBG("Using SEQPACKET socket\n");
                type = SOCK_SEQPACKET;
        } else {
                DBG("Using STREAM socket\n");
                type = SOCK_STREAM;
        }

        ctx.sock = socket( domain, type, IPPROTO_SCTP );
        if ( ctx.sock < 0 ) {
                fprintf(stderr, "Unable to create socket: %s \n", strerror(errno));
                return EXIT_FAILURE;
        }

        do_client( &ctx );
        return EXIT_SUCCESS;
}



        









