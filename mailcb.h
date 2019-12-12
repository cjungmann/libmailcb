#ifndef MAILCB_H
#define MAILCB_H

#include <sys/types.h>

#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/bio.h>

#include "socktalk.h"

// prototype for MParcel to be used for function pointer
struct _comm_parcel;

typedef void (*ServerReady)(struct _comm_parcel *parcel);

typedef struct _smtp_args
{
   const char *host;
   const char *login;
   const char *password;
   int port;
   int use_tls;
} SmtpArgs;

typedef struct _smtp_caps
{
   /** Server-reported capabilities */
   int cap_starttls;
   int cap_enhancedstatuscodes;
   int cap_8bitmime;
   int cap_7bitmime;
   int cap_pipelining;
   int cap_chunking;
   int cap_smtputf8;
   int cap_size;
   int cap_auth_any;
   int cap_auth_plain;        // use base64 encoding
   int cap_auth_login;        // use base64 encoding
   int cap_auth_gssapi;
   int cap_auth_digest_md5;
   int cap_auth_md5;
   int cap_auth_cram_md5;
   int cap_auth_oauth10a;
   int cap_auth_oauthbearer;
   int cap_auth_xoauth;
   int cap_auth_xoauth2;
} SmtpCaps;

typedef struct _comm_parcel
{
   /** Details for making the mail connection. */
   const char *host_url;
   int host_port;
   int starttls;

   int pop_reader;

   /** Tracking variables */
   int total_sent;
   int total_read;

   /** SMTP server login credentials */
   const char *login;
   const char *password;
   const char *user;

   /** Points to a config file section from which connection information can be read. */
   const char *account;   // Only used if a config file had been opened.

   /** Reporting fields */
   int verbose;
   int quiet;
   const char *logfilepath;
   FILE *logfile;

   /** Server communication conduit */
   STalker *stalker;

   /** Enclosed struct to make it easier to clear for multiple settings. */
   SmtpCaps caps;

   /** User-discretion pointer */
   void *data;

   ServerReady callback_func;

} MParcel;


#include "commparcel.h"

void advise_message(const MParcel *mp, ...);
void log_message(const MParcel *mp, ...);

int send_data(MParcel *mp, ...);
int recv_data(MParcel *mp, char *buffer, int len);

int digits_in_base(int value, int base);
int itoa_buff(int value, int base, char *buffer, int buffer_len);

void parse_greeting_response(MParcel *parcel, const char *buffer, int buffer_len);

int get_connected_socket(const char *host_url, int port);



int authorize_session(MParcel *parcel);

int greet_smtp_server(MParcel *parcel, int socket_handle);
void start_ssl(MParcel *parcel, int socket_handle);

void notify_mailer(MParcel *parcel);

void open_ssl(MParcel *parcel, int socket_handle, ServerReady talker_user);
void prepare_talker(MParcel *parcel, ServerReady talker_user);


void send_email(MParcel *parcel,
                const char **recipients,
                const char **headers,
                const char *msg);




#endif  // MAILCB_H
