

CC	= gcc
CFLAGS	= -Wall -Wextra -Wshadow -g -std=gnu99
ifeq ($(FREEBSD),1)
CFLAGS += -DFREEBSD
else
LFLAGS	= -lsctp
endif


COMMON_OBJS	= debug.o common.o
CLIENT_OBJS	= $(COMMON_OBJS) sctp_client.o 
CLIENT_NAME	= sctp-cli

SERVER_OBJS	= $(COMMON_OBJS) sctp_server.o
SERVER_NAME	= sctp-srv

.PHONY	: all clean cli srv

all	: cli srv

cli	: $(CLIENT_OBJS)
	$(CC) -o $(CLIENT_NAME) $(CLIENT_OBJS) $(LFLAGS)

srv	: $(SERVER_OBJS)
	$(CC) -o $(SERVER_NAME) $(SERVER_OBJS) $(LFLAGS)

%.o	: src/%.c 
	$(CC) $(CFLAGS) -c $< -o $@

clean	:
	rm -f $(CLIENT_NAME) $(SERVER_NAME) *.o core.*
