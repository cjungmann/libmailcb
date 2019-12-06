#ifndef MAILCB_H
#define MAILCB_H

#include <sys/types.h>

#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/bio.h>

#include "socktalk.h"

typedef struct _smtp_args
{
   const char *host;
   const char *login;
   const char *password;
   int port;
   int use_tls;
} SmtpArgs;

typedef struct _comm_parcel
{
   /** requested options */
   const char *host_url;
   int host_port;
   int starttls;

   const char *login;
   const char *password;
   const char *user;


   /** Server communication conduit */
   STalker *stalker;

   /** Server-reported capabilities */
   int cap_starttls;
   int cap_enhancedstatuscodes;
   int cap_8bitmime;
   int cap_7bitmime;
   int cap_pipelining;
   int cap_chunking;
   int cap_smtputf8;
   int cap_size;
   int cap_auth_plain;        // use base64 encoding
   int cap_auth_login;        // use base64 encoding
   int cap_auth_gssapi;
   int cap_auth_digest_md5;
   int cap_auth_md5;
   int cap_auth_cram_md5;
   int cap_auth_oauth10a;
   int cap_auth_oauthbearer;
} MParcel;

int digits_in_base(int value, int base);
int itoa_buff(int value, int base, char *buffer, int buffer_len);

void parse_greeting_response(MParcel *parcel, const char *buffer, int buffer_len);

int get_connected_socket(const char *host_url, int port);

int greet_server(MParcel *parcel, int socket_handle);



#endif  // MAILCB_H
