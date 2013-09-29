/**
 * @file sctp_events.c - Generic handler for ancillary SCTP events.
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

#define DBG_MODULE_NAME DBG_MODULE_EVENTS
#include "defs.h"
#include "debug.h"
#include "common.h"

/**
 * Print information about SCTP_ASSOC_CHANGE event 
 *
 * @param assoc_ch Pointer to the structure containing event details.
 */
static void verbose_assoc_event( struct sctp_assoc_change *assoc_ch )
{
        if (assoc_ch->sac_type != SCTP_ASSOC_CHANGE) {
                WARN("Invalid sac_type for sctp_assoc_change (%d)!\n",
                                assoc_ch->sac_type);
                return;
        }

        switch( assoc_ch->sac_state ) {
                case SCTP_COMM_UP :
                        printf("##Association %d established\n", 
                                        assoc_ch->sac_assoc_id);
                        printf("##with %d output and %d input streams\n",
                                        assoc_ch->sac_inbound_streams,
                                        assoc_ch->sac_outbound_streams);
                        break;
                case SCTP_COMM_LOST :
                        printf("##Association %d lost (Error 0x%.4x)\n",
                                        assoc_ch->sac_assoc_id,
                                        assoc_ch->sac_error);
                        break;
                case SCTP_RESTART :
                        printf("##Association %d restarted\n",
                                        assoc_ch->sac_assoc_id);
                        break;
                case SCTP_SHUTDOWN_COMP :
                        printf("##Association %d shut down\n",
                                        assoc_ch->sac_assoc_id);
                        break;
                case SCTP_CANT_STR_ASSOC :
                        printf("##Unable to create association\n");
                        break;
                default :
                        WARN("Unexpected state for SCTP_ASSOC_CHANGE (%d)\n",
                                        assoc_ch->sac_state);
                        break;
        }
}

/**
 * Print verbose information about incoming SHUTDOWN_EVENT.
 * @param shut The event data.
 */
static void verbose_shutdown_event( struct sctp_shutdown_event *shut )
{
        printf("##SHUTDOWN received for association %d\n", 
                        shut->sse_assoc_id);
}

/**
 * Print verbose information about incoming SEND_FAILED event.
 * @Param ssf The event data.
 */
static void verbose_send_failed_event( struct sctp_send_failed *ssf)
{
        printf("##SEND FAILURE for association %d\n", ssf->ssf_assoc_id);
        printf("##Data was ");
        if (ssf->ssf_flags & SCTP_DATA_UNSENT ) 
                printf("not ");
        printf("put to wire!");
}

/**
 * Print verbose information about incoming SCTP_AUTHKEY_EVENT.
 * @param sae The event data
 */
static void verbose_auth_event(struct sctp_authkey_event *sae)
{
        printf("##AUTHENTICATION_EVENT for association %d\n", sae->auth_assoc_id);
        printf("##Key %d ", sae->auth_keynumber);
        switch(sae->auth_indication) {
                case SCTP_AUTH_NEWKEY :
                        printf(" has been made active\n");
                        break;
/* No support for these in Linux */
#if 0
                case SCTP_AUTH_NO_AUTH :
                        printf(" - Peer does not support authentication\n");
                        break;
                case SCTP_AUTH_FREE_KEY :
                        printf(" no longer used\n");
                        break;
#endif
                default :
                        printf(" - Unknown indication 0x%.8x\n",
                                        sae->auth_indication);
                        break;
        }
}

#ifndef SCTP_AUTHENTICATION_EVENT
/* for some reason /usr/include/netinet/sctp.h has _INDICATION
 * instead of _EVENT.  The struct is same, though
 */
#define SCTP_AUTHENTICATION_EVENT SCTP_AUTHENTICATION_INDICATION
#endif /* no SCTP_AUTHENTICATION_EVENT */

/**
 * Handle incoming SCTP ancillary event. 
 *
 * @param data The event as it was received from socket.
 * @return 0 if the event was handled ok.
 */
int handle_event( uint8_t *data )
{
        union sctp_notification *not = (union sctp_notification *)data;

        switch( not->sn_header.sn_type ) {
                case SCTP_ASSOC_CHANGE :
                        verbose_assoc_event(&(not->sn_assoc_change));
                        break;
                case SCTP_SHUTDOWN_EVENT :
                        verbose_shutdown_event(&(not->sn_shutdown_event));
                        break;
                case SCTP_SEND_FAILED :
                        verbose_send_failed_event(&(not->sn_send_failed));
                        break;
                case SCTP_AUTHENTICATION_EVENT :
#ifdef FREEBSD
                        verbose_auth_event(&(not->sn_auth_event));
#else
                        /* Linux has named this event sn_authkey_event
                         * RFC 6458 says that it should be sb_auth_event
                         */
                        verbose_auth_event(&(not->sn_authkey_event));
#endif /* FREEBSD */
                        break;
                default :
                        TRACE("Discarding event with unknown type %d \n",
                                        not->sn_header.sn_type);
        }
        return 0;
}
