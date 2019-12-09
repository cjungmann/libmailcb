BASEFLAGS = -Wall -Werror -m64
LIB_CFLAGS = ${BASEFLAGS} -I. -fPIC -shared

LOCAL_LINK = -Wl,-R -Wl,. -lmailcb

debug : BASEFLAGS  += -ggdb -DDEBUG

CC = cc

all : libmailcb.so mailer

libmailcb.so : libmailcb.c mailcb.h socktalk.o socktalk.h commparcel.c
	$(CC) $(LIB_CFLAGS) -o libmailcb.so socktalk.o libmailcb.c -lssl -lcrypto -lcode64

socktalk.o : socktalk.c socktalk.h
	$(CC) $(LIB_CFLAGS) -c -o socktalk.o socktalk.c

clean :
	rm -f libmailcb.so libmailcbd.so socktalk.o socktalkd.o mcbtest

mailer : mailer.c libmailcb.so mailcb.h
	$(CC) $(BASEFLAGS) -L. -o mailer mailer.c $(LOCAL_LINK) -lreadini

debug: libmailcb.c mailcb.h mcbtest.c socktalk.o socktalk.h commparcel.c mailer.c
	$(CC) $(LIB_CFLAGS) -c -o socktalkd.o socktalk.c
	$(CC) $(LIB_CFLAGS) -o libmailcbd.so socktalkd.o libmailcb.c -lssl -lcrypto -lcode64
	$(CC) $(BASEFLAGS) -L. -o mcbtest mcbtest.c $(LOCAL_LINK)d
	$(CC) $(BASEFLAGS) -L. -o mailerd mailer.c $(LOCAL_LINK)d -lreadini

# install :
# 	install -D --mode=755 libreadini.so /usr/lib
# 	install -D --mode=755 readini.h     /usr/local/include

# uninstall :
# 	rm -f /usr/lib/libreadini.so
# 	rm -f /usr/local/include/readini.h
