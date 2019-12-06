BASEFLAGS = -Wall -Werror -m64
LIB_CFLAGS = ${BASEFLAGS} -I. -fPIC -shared

LOCAL_LINK = -Wl,-R -Wl,. -lmailcb

debug : BASEFLAGS  += -ggdb -DDEBUG

CC = cc

all : libmailcb.so

libmailcb.so : libmailcb.c mailcb.h socktalk.o socktalk.h commparcel.c
	$(CC) $(LIB_CFLAGS) -o libmailcb.so socktalk.o libmailcb.c -lssl -lcrypto -lcode64

socktalk.o : socktalk.c socktalk.h
	$(CC) $(LIB_CFLAGS) -c -o socktalk.o socktalk.c

clean :
	rm -f libmailcb.so libmailcbd.so socktalk.o socktalkd.o mcbtest

debug: libmailcb.c mailcb.h mcbtest.c
	$(CC) $(LIB_CFLAGS) -c -o socktalkd.o socktalk.c
	$(CC) $(LIB_CFLAGS) -o libmailcbd.so socktalkd.o libmailcb.c -lssl -lcrypto -lcode64
	$(CC) $(BASEFLAGS) -L. -o mcbtest mcbtest.c $(LOCAL_LINK)d

# install :
# 	install -D --mode=755 libreadini.so /usr/lib
# 	install -D --mode=755 readini.h     /usr/local/include

# uninstall :
# 	rm -f /usr/lib/libreadini.so
# 	rm -f /usr/local/include/readini.h
