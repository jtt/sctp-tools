/**
 * @file common.h 
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
#ifndef _COMMON_H_
#define _COMMON_H_


typedef uint16_t flags_t;

flags_t set_flag( flags_t flags, flags_t set );
int is_flag( flags_t flags, flags_t set );
flags_t unset_flag( flags_t flags, flags_t set );

int resolve( char *addr, struct sockaddr_storage *ss );
int parse_uint16( char *str, uint16_t *dst );

int sendit_seq( int sock, uint16_t ppid, uint16_t streamno,
                struct sockaddr *dst, size_t dst_len,
                uint8_t *chunk, int chunk_size );
int recv_wait( int sock, time_t timeout_ms, uint8_t *chunk, size_t chunk_len,
                struct sockaddr *peer, socklen_t *peerlen, struct sctp_sndrcvinfo *info,
                int *flags );
void print_error( const char *msg, int num );
#endif /* _COMMON_H_ */
