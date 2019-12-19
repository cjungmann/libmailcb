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
struct _pop_closure;

typedef struct _header_field
{
   const char *name;
   const char *value;
   struct _header_field *next;
} HeaderField;

typedef void (*ServerReady)(struct _comm_parcel *parcel);

typedef int (*NextPOPMessageHeader)(struct _comm_parcel *parcel, struct _pop_closure *pop_closure );

/**
 * @brief The POP message handler will call this function for every message on the server.
 *
 * @return 1 to continue receiving messages, 0 to signal library to stop sending messages.
 */
typedef int (*PopPushedMessage)(struct _pop_closure *pop_closure, const HeaderField *fields);

typedef struct _smtp_args
{
   const char *host;
   const char *login;
   const char *password;
   int port;
   int use_tls;
} SmtpArgs;

typedef struct _pop_closure
{
   struct _comm_parcel *parcel;
   int message_count;
   int inbox_size;
   int message_index;
} PopClosure;


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

   /** for FROM: field in outgoing emails. */
   const char *from;

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

   PopPushedMessage pop_message_receiver;

} MParcel;


#include "commparcel.h"

int is_opening_smtp(const MParcel *parcel) { return !parcel->pop_reader; }

void parse_smtp_greeting_response(MParcel *parcel, const char *buffer, int buffer_len);

int get_connected_socket(const char *host_url, int port);



int authorize_smtp_session(MParcel *parcel);

void notify_mailer(MParcel *parcel);

void open_ssl(MParcel *parcel, int socket_handle, ServerReady talker_user);

int parse_header_field(const char *start,
                       const char *end_of_buffer,
                       const char **tag,
                       int *tag_len,
                       const char **value,
                       int *value_len);

void trim_copy_value(char *target, const char *source, int source_len);
int send_pop_message_header(PopClosure *popc);

/** Public functions, all should start with mcb_ */

void mcb_advise_message(const MParcel *mp, ...);
void mcb_log_message(const MParcel *mp, ...);

int mcb_send_data(MParcel *mp, ...);
int mcb_recv_data(MParcel *mp, char *buffer, int len);

int mcb_digits_in_base(int value, int base);
int mcb_itoa_buff(int value, int base, char *buffer, int buffer_len);

int mcb_greet_smtp_server(MParcel *parcel);
void mcb_quit_smtp_server(MParcel *parcel);
void mcb_greet_pop_server(MParcel *parcel);

void mcb_prepare_talker(MParcel *parcel, ServerReady talker_user);


void mcb_send_email(MParcel *parcel,
                    const char **recipients,
                    const char **headers,
                    const char *msg);




#endif  // MAILCB_H
