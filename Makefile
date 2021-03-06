BASEFLAGS = -Wall -Werror
LIB_CFLAGS = ${BASEFLAGS} -I. -fPIC -shared

LOCAL_LINK = -Wl,-R -Wl,. -lmailcb
LOCAL_LINKD = -Wl,-R -Wl,. -lmailcbd
MODULES = buffread.o commparcel.o mailcb_smtp.o simple_email.o socktalk.o

debug : BASEFLAGS  += -ggdb -DDEBUG

CC = cc

all : libmailcb.so mailer sample_smtp

libmailcb.so : libmailcb.c mailcb.h mailcb_internal.h socktalk.h buffread.h commparcel.c $(MODULES)
	$(CC) $(LIB_CFLAGS) -o libmailcb.so $(MODULES) libmailcb.c -lssl -lcrypto -lcode64

mailcb_smtp.o : mailcb_smtp.c mailcb.h mailcb_internal.h socktalk.h commparcel.h
	$(CC) $(LIB_CFLAGS) -c -o mailcb_smtp.o mailcb_smtp.c

buffread.o : buffread.c buffread.h
	$(CC) $(LIB_CFLAGS) -c -o buffread.o buffread.c

commparcel.o : commparcel.c commparcel.h mailcb.h
	$(CC) $(LIB_CFLAGS) -c -o commparcel.o commparcel.c

simple_email.o : simple_email.c mailcb.h mailcb_internal.h socktalk.h buffread.h
	$(CC) $(LIB_CFLAGS) -c -o simple_email.o simple_email.c

socktalk.o : socktalk.c socktalk.h
	$(CC) $(LIB_CFLAGS) -c -o socktalk.o socktalk.c

clean :
	rm -f *.so *.o mailer mailerd

mailer : mailer.c libmailcb.so mailcb.h
	$(CC) $(BASEFLAGS) -L. -o mailer mailer.c $(LOCAL_LINK) -lreadini

sample_smtp : sample_smtp.c libmailcb.so mailcb.h
	$(CC) $(BASEFLAGS) -L. -o sample_smtp sample_smtp.c $(LOCAL_LINK) -lreadini

debug: libmailcb.c mailcb.h mailcb_internal.h socktalk.c socktalk.h buffread.c buffread.h commparcel.c commparcel.h mailer.c
	$(CC) $(LIB_CFLAGS) -c -o socktalkd.o socktalk.c
	$(CC) $(LIB_CFLAGS) -c -o commparceld.o commparcel.c
	$(CC) $(LIB_CFLAGS) -c -o mailcb_smtpd.o mailcb_smtp.c
	$(CC) $(LIB_CFLAGS) -c -o buffreadd.o buffread.c
	$(CC) $(LIB_CFLAGS) -c -o simple_emaild.o simple_email.c
	$(CC) $(LIB_CFLAGS) -o libmailcbd.so socktalkd.o mailcb_smtpd.o buffreadd.o commparceld.o simple_emaild.o libmailcb.c -lssl -lcrypto -lcode64
	$(CC) $(BASEFLAGS) -L. -o mailerd mailer.c $(LOCAL_LINK)d -lreadini
	$(CC) $(BASEFLAGS) -L. -o sample_smtpd sample_smtp.c $(LOCAL_LINK) -lreadini

install :
	install -D --mode=755 libmailcb.so /usr/lib
	install -D --mode=755 mailcb.h     /usr/local/include
	install -D --mode=755 mailer       /usr/local/bin

uninstall :
	rm -f /usr/lib/libmailcb.so
	rm -f /usr/local/include/mailcb.h
	rm -f /usr/loca/bin/mailer
