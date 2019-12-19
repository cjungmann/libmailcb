BASEFLAGS = -Wall -Werror -m64
LIB_CFLAGS = ${BASEFLAGS} -I. -fPIC -shared

LOCAL_LINK = -Wl,-R -Wl,. -lmailcb

debug : BASEFLAGS  += -ggdb -DDEBUG

CC = cc

all : libmailcb.so mailer

libmailcb.so : libmailcb.c mailcb.h mailcb_internal.c socktalk.o socktalk.h commparcel.c
	$(CC) $(LIB_CFLAGS) -o libmailcb.so socktalk.o libmailcb.c -lssl -lcrypto -lcode64

socktalk.o : socktalk.c socktalk.h
	$(CC) $(LIB_CFLAGS) -c -o socktalk.o socktalk.c

clean :
	rm -f libmailcb.so libmailcbd.so socktalk.o socktalkd.o mailer mailerd

mailer : mailer.c libmailcb.so mailcb.h
	$(CC) $(BASEFLAGS) -L. -o mailer mailer.c $(LOCAL_LINK) -lreadini

debug: libmailcb.c mailcb.h mailcb_internal.h socktalk.o socktalk.h commparcel.c commparcel.h mailer.c
	$(CC) $(LIB_CFLAGS) -c -o socktalkd.o socktalk.c
	$(CC) $(LIB_CFLAGS) -o libmailcbd.so socktalkd.o libmailcb.c -lssl -lcrypto -lcode64
	$(CC) $(BASEFLAGS) -L. -o mailerd mailer.c $(LOCAL_LINK)d -lreadini

install :
	install -D --mode=755 libmailcb.so /usr/lib
	install -D --mode=755 mailcb.h     /usr/local/include
	install -D --mode=755 mailer       /usr/local/bin

uninstall :
	rm -f /usr/lib/libmailcb.so
	rm -f /usr/local/include/mailcb.h
	rm -f /usr/loca/bin/mailer
