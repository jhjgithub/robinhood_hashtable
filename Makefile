CFLAGS=-std=c99
CFLAGS+=-W -Wall -Wextra
CFLAGS+=-g -ggdb

.PHONY: all clean
all: robinhood_hashtable

clean:
	$(RM) robinhood_hashtable
