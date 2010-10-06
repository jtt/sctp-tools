/**
 * @file sctp_server.c Simple SCTP server 
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

#include <sys/select.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>

#define DBG_MODULE_NAME DBG_MODULE_SERVER

#include "defs.h"
#include "debug.h"
#include "common.h"
#include "sctp_events.h"

#define DEFAULT_PORT 2001
#define DEFAULT_BACKLOG 2

#define RECVBUF_SIZE 1024

#define PROG_VERSION "0.0.2"

/* Operation flags */
#define VERBOSE_FLAG 0x01
#define SEQPKT_FLAG 0x01 <<1 
#define ECHO_FLAG 0x01 <<2
/**
 * Number of milliseconds to wait on select() before checking if user has
 * requested stop.
 */
#define ACCEPT_TIMEOUT_MS 100

#ifdef FREEBSD
/* FreeBSD setsockopt() wants the protocol number as the 'level'
 * parameter, Linux uses SOL_SCTP, we'll define that here for
 * FreeBSD
 */
#define SOL_SCTP 132
#endif /* FREEBSD */


/**
 * Indication that user has requested close
 */
static int close_req = 0;

/**
 * The main context.
 */
struct server_ctx {
        int sock; /**< Socket we are listening for connections */
        uint16_t port; /**< Port we are listening on */
        uint8_t *recvbuf; /**< Buffer where data is received */
        uint16_t recvbuf_size; /**< Number of bytes of data on buffer */
        struct partial_store partial; /**< partial datagrams collected here */
        flags_t options;/**< Operation flags */
        struct sctp_initmsg *initmsg; /**< association parameters, if set */
};

/**
 * Bind to requested port and set the socket to listen for incoming
 * connections.
 * The port is read from the main context.
 *
 * @param ctx Pointer to the main context.
 * @return -1 if operation failed, 0 on success.
 */
int bind_and_listen( struct server_ctx *ctx )
{
        struct sockaddr_in6 ss;

        DBG("Binding to port %d \n", ctx->port );
        memset( &ss, 0, sizeof( ss ));
        ss.sin6_family = AF_INET6;

        ss.sin6_port = htons(ctx->port);

        memcpy( &ss.sin6_addr, &in6addr_any, sizeof(struct in6_addr));
        if ( bind(ctx->sock, (struct sockaddr *)&ss, sizeof( struct sockaddr_in6)) < 0 ) {
                print_error( "Unable to bind()", errno );
                return -1;
        }

        if ( listen( ctx->sock, DEFAULT_BACKLOG ) < 0 ) {
                print_error(" Unable to listen()", errno );
                return -1;
        }

        return 0;
}


/**
 * Wait for incoming connection.
 *
 * Returns either when a connection from remote server accepted or if stop_req
 * is set to 1.
 *
 * @param ctx Pointer to main context.
 * @param remote_ss Address of the remote host is saved here.
 * @param addrlen Pointer to variable where lenght of remote host data is saved.
 * @return -1 on error, the fd for accepted connection on success.
 */
int do_accept( struct server_ctx *ctx, struct sockaddr_storage *remote_ss, 
                socklen_t *addrlen )
{
        int cli_fd = 0, ret = 0;
        fd_set fds;
        struct timeval tv;

        while( ret == 0 ) {
                if ( close_req )
                        return 0;

                FD_ZERO( &fds );
                FD_SET( ctx->sock, &fds );

                memset( &tv, 0, sizeof(tv));

                tv.tv_usec = ACCEPT_TIMEOUT_MS * 1000;

                ret = select( ctx->sock+1, &fds, NULL, NULL, &tv );
                if ( ret > 0 && FD_ISSET( ctx->sock, &fds ) )  {
                        TRACE("Going to accept()\n");
                        cli_fd = accept( ctx->sock, (struct sockaddr *)remote_ss, 
                                        addrlen );
                        if ( cli_fd < 0 ) {
                                if ( errno == EINTR ) 
                                        continue; /* likely we are closing */

                                print_error( "Error in accept()", errno);
#ifdef IGNORE_ACCEPT_ERROR
                                ret = 0;
                                continue;
#else
                                return -1;
#endif /* IGNORE_ACCEPT_ERROR */
                        }
                } else if ( ret < 0 ) {
                        if ( errno == EINTR ) 
                                continue;

                        print_error( "Error in select()", errno);
                        return -1;
                }
        }
        return cli_fd;
}
/* do_server() return values */

#define SERVER_USER_CLOSE 0
#define SERVER_ERROR -1
#define SERVER_REMOTE_CLOSED -2

/**
 * Server loop. 
 *
 * Wait for incoming data from remote peer and if echo mode is on, echo it
 * back.
 * 
 * @param ctx Pointer to main context.
 * @param fd The socket to the remote peer (in SOCK_STREAM mode) or the "server
 * socket" in SOCK_SEQPKT mode.
 * @return SERVER_USER_CLOSE if user requested stop (ctrl+c was pressed),
 * SERVER_ERROR if there was error when receiving data, SERVER_OK if the remote
 * end closed connetion.
 */
int do_server( struct server_ctx *ctx, int fd ) 
{
        struct sockaddr_storage peer_ss;
        socklen_t peerlen;
        struct sctp_sndrcvinfo info;
        int ret,flags;
        char peername[INET6_ADDRSTRLEN];
        void *ptr;
        uint16_t port;

        while( ! close_req ) {

                memset( &peer_ss, 0, sizeof( peer_ss ));
                memset( &info, 0, sizeof( peer_ss ));
                peerlen = sizeof( struct sockaddr_in6);
                flags = 0;

                ret = recv_wait( fd, ACCEPT_TIMEOUT_MS,
                                ctx->recvbuf, ctx->recvbuf_size, 
                                (struct sockaddr *)&peer_ss, &peerlen,
                                &info, &flags );
                if ( ret == -1 ) {
                        if ( errno == EINTR )
                                continue;

                        print_error("Unable to read data", errno);
                        return SERVER_ERROR;
                } else if ( ret == -2 )  {
                        printf("Connection closed by remote host\n" );
                        return SERVER_REMOTE_CLOSED;
                } else if ( ret > 0 ) {
                        DBG("Received %d bytes \n", ret );
                        partial_store_collect(&ctx->partial, ctx->recvbuf, ret);

                        if ( flags & MSG_NOTIFICATION ) {
                                TRACE("Received SCTP event\n");
                                if ( flags & MSG_EOR ) {
                                        handle_event(partial_store_dataptr(&ctx->partial));
                                        partial_store_flush(&ctx->partial);
                                } 
                                continue;
                        }

                        if ( peer_ss.ss_family == AF_INET ) {
                                ptr = &(((struct sockaddr_in *)&peer_ss)->sin_addr);
                                port = ((struct sockaddr_in *)&peer_ss)->sin_port;
                        } else {
                                ptr = &(((struct sockaddr_in6 *)&peer_ss)->sin6_addr);
                                port = ((struct sockaddr_in6 *)&peer_ss)->sin6_port;
                        }
                        if ( inet_ntop(peer_ss.ss_family, ptr, peername, peerlen ) != NULL ) {
                                printf("Packet from %s:%d ", peername, ntohs(port));
                        } else {
                                printf("Packet from unknown");
                        }
                        printf(" with %d bytes of data", ret);
                        if ( !(flags & MSG_EOR) )
                                printf(" (partial data)");
                        
                        printf("\n");

                        if ( is_flag( ctx->options, VERBOSE_FLAG ) ) {
                                printf("\t stream: %d ppid: %d context: %d\n", info.sinfo_stream, 
                                                info.sinfo_ppid, info.sinfo_context );
                                printf("\t ssn: %d tsn: %u cumtsn: %u ", info.sinfo_ssn, 
                                                info.sinfo_tsn, info.sinfo_cumtsn );
                                printf("[");
                                if ( info.sinfo_flags & SCTP_UNORDERED ) 
                                  printf("un");
                                printf("ordered]\n");
                                xdump_data( stdout, ctx->recvbuf, ret, "Received data" );
                                  
                        }
                        if ( is_flag( ctx->options, ECHO_FLAG ) && (flags & MSG_EOR) ) {
                                DBG("Echoing data back\n");
                                if ( sendit( fd, info.sinfo_ppid, info.sinfo_stream,
                                             (struct sockaddr *)&peer_ss, peerlen,
                                              partial_store_dataptr( &ctx->partial),
                                              partial_store_len( &ctx->partial) ) < 0) {
                                        WARN("Error while echoing data!\n");
                                }
                        }
                        if ( flags & MSG_EOR ) 
                                partial_store_flush( &ctx->partial );
                }
        }
        return SERVER_USER_CLOSE;
}


/**
 * Signal handler for handling user pressing ctrl+c.
 * @param sig Signal received.
 */
void sighandler( int sig )
{
        DBG("Received signal %d \n", sig );
        if ( sig == SIGPIPE ) {
                WARN("Received SIGPIPE, closing down\n");
        }

        close_req = 1;
}

static void print_usage() 
{
        printf("sctp_server v%s\n", PROG_VERSION );
        printf("Usage: sctp_server [options] \n");
        printf("Available options are: \n" );
        printf("\t--port <port>  : listen on local port <p>, default %d \n", DEFAULT_PORT);
        printf("\t--buf <size>   : Size of rceive buffer is <size>, default is %d\n",
                      RECVBUF_SIZE);
        printf("\t--seq          : use SOCK_SEQPACKET socket instead of SOCK_STREAM\n");
        printf("\t--echo         : Echo the received data back to sender\n");
        printf("\t--verbose      : Be more verbosive \n");
        printf("\t--instreams       : Maximum number of input streams to negotiate for the association\n");
        printf("\t--outstreams      : Number of output streams to negotiate\n");
        printf("\t--help         : Print this message \n");
}  

static int parse_args( int argc, char **argv, struct server_ctx *ctx )
{
        int c, option_index;
        uint16_t streams;
        struct option long_options[] = {
                { "port", 1, 0, 'p' },
                { "help", 0,0, 'H' },
                { "buf", 1,0,'b' },
                { "seq", 0,0,'s' },
                { "echo",0,0,'e' },
                { "verbose", 0,0,'v'},
                { "instreams", 1,0, 'I' },
                { "outstreams", 1,0,'O' },
                { 0,0,0,0 }
        };

        while (1) {

                c = getopt_long( argc, argv, "p:b:HsevI:O:", long_options, &option_index );
                if ( c == -1 )
                        break;

                switch (c) {
                        case 'p' :
                                if ( parse_uint16( optarg, &(ctx->port)) < 0 ) {
                                        fprintf(stderr, "Malformed port given\n" );
                                        return -1;
                                }
                                break;
                        case 'b' :
                                if ( parse_uint16( optarg, &(ctx->recvbuf_size)) < 0 ) {
                                        fprintf(stderr, "Illegal recv buffer size given\n");
                                        return -1;
                                }
                                break;
                        case 's' :
                                ctx->options = set_flag( ctx->options, SEQPKT_FLAG );
                                break;
                        case 'e' :
                                ctx->options = set_flag( ctx->options, ECHO_FLAG );
                                break;
                        case 'v' :
                                ctx->options = set_flag( ctx->options, VERBOSE_FLAG );
                                break;
                        case 'I' :
                                if (parse_uint16(optarg, &streams) < 0 ) {
                                        fprintf(stderr, "Invalid input stream count given\n");
                                        return -1;
                                }
                                if (ctx->initmsg == NULL ) {
                                        ctx->initmsg = mem_alloc( sizeof(struct sctp_initmsg));
                                        memset( ctx->initmsg, 0, sizeof(struct sctp_initmsg));
                                }
                                ctx->initmsg->sinit_max_instreams = streams;
                                break;
                        case 'O' :
                                if (parse_uint16(optarg, &streams) < 0 ) {
                                        fprintf(stderr,"Invalid output stream count given\n");
                                        return -1;
                                }
                                if (ctx->initmsg == NULL) {
                                        ctx->initmsg = mem_alloc(sizeof(*ctx->initmsg));
                                        memset( ctx->initmsg,0,sizeof(*ctx->initmsg));
                                }
                                ctx->initmsg->sinit_num_ostreams = streams;
                                break;
                        case 'H' :
                        default :
                                print_usage();
                                return 0;
                                break;
                }
        }

        return 1;
}

int main( int argc, char *argv[] )
{
        struct sockaddr_storage myaddr,remote;
        struct server_ctx ctx;
        int cli_fd, ret;
        socklen_t addrlen;
        char peer[INET6_ADDRSTRLEN];
        void *ptr;

        if ( signal( SIGTERM, sighandler ) == SIG_ERR ) {
                fprintf(stderr, "Unable to set signal handler\n");
                return EXIT_FAILURE;
        }
        if ( signal( SIGINT, sighandler ) == SIG_ERR ) {
                fprintf(stderr, "Unable to set signal handler\n");
                return EXIT_FAILURE;
        }
        if ( signal( SIGPIPE, sighandler ) == SIG_ERR ) {
                fprintf(stderr, "Unable to set signal handler\n");
                return EXIT_FAILURE;
        }

        memset( &ctx, 0, sizeof( ctx ));
        ctx.port = DEFAULT_PORT;
        ctx.recvbuf_size = RECVBUF_SIZE;

        partial_store_init(&ctx.partial);

        ret = parse_args( argc, argv, &ctx );
        if ( ret  < 0 ) {
                WARN("Error while parsing command line\n" );
                return EXIT_FAILURE;
        } else if ( ret == 0 ) {
                return EXIT_SUCCESS;
        }
        

        memset( &myaddr, 0, sizeof( myaddr));
        myaddr.ss_family = AF_INET6;

        if ( is_flag( ctx.options, SEQPKT_FLAG )) {
                DBG("Using SEQPKT socket\n");
                ctx.sock = socket( PF_INET6, SOCK_SEQPACKET, IPPROTO_SCTP );
        } else {
                DBG("Using STREAM socket\n");
                ctx.sock = socket( PF_INET6, SOCK_STREAM, IPPROTO_SCTP );
        }
        if ( ctx.sock < 0 ) {
                fprintf(stderr, "Unable to create socket: %s \n", strerror(errno));
                return EXIT_FAILURE;
        }
        if (ctx.initmsg != NULL ) {
                TRACE("Requesting for %d output streams and at max %d input streams\n",
                                ctx.initmsg->sinit_num_ostreams,
                                ctx.initmsg->sinit_max_instreams);
                if (setsockopt( ctx.sock, SOL_SCTP, SCTP_INITMSG, 
                                        ctx.initmsg, sizeof(*ctx.initmsg)) < 0) {
                        fprintf(stderr,"Warning: unable to set the association parameters: %s\n",
                                        strerror(errno));
                }
        }

        if ( bind_and_listen( &ctx ) < 0 ) {
                fprintf(stderr, "Error while initializing the server\n" );
                close(ctx.sock);
                return EXIT_FAILURE;
        }

        if ( is_flag( ctx.options, VERBOSE_FLAG ))  
                subscribe_to_events(ctx.sock); /* to err is not fatal */

        memset( &remote, 0, sizeof(remote));
        addrlen = sizeof( struct sockaddr_in6);

        TRACE("Allocating %d bytes for recv buffer \n", ctx.recvbuf_size );
        ctx.recvbuf = mem_alloc( ctx.recvbuf_size * sizeof( uint8_t ));

        printf("Listening on port %d \n", ctx.port );
        while ( !close_req ) {
                if ( is_flag( ctx.options, SEQPKT_FLAG ) ) {
                        ret = do_server( &ctx, ctx.sock );
                        if ( ret == SERVER_ERROR )
                                break;
                } else {
                        cli_fd = do_accept( &ctx, &remote, &addrlen );
                        if ( cli_fd < 0 ) {
                                if ( errno == EINTR ) 
                                        break;

                                close( ctx.sock );
                                mem_free( ctx.recvbuf);
                                WARN( "Error in accept!\n");
                                return EXIT_FAILURE;
                        } else if ( cli_fd == 0 ) {
                                break;
                        }
                        if ( remote.ss_family == AF_INET ) {
                                ptr = &(((struct sockaddr_in *)&remote)->sin_addr);
                        } else {
                                ptr = &(((struct sockaddr_in6 *)&remote)->sin6_addr);
                        }
                        if ( inet_ntop(remote.ss_family, ptr, peer,
                                                INET6_ADDRSTRLEN ) != NULL ) {
                                printf("Connection from %s \n", peer );
                        } else {
                                printf("Connection from unknown\n");
                        }
                        if( do_server( &ctx, cli_fd ) == SERVER_ERROR ) {
                                close( cli_fd);
                                break;
                        }
                        close( cli_fd );
                }
        }
        mem_free( ctx.recvbuf);
        if (ctx.initmsg != NULL ) {
                mem_free( ctx.initmsg);
        }
        close( ctx.sock );

        return EXIT_SUCCESS;
}
