#ifndef MAILCB_H
#define MAILCB_H

#include <sys/types.h>
#include "socktalk.h"
#include "buffread.h"

// prototype for MParcel to be used for function pointer
struct _comm_parcel;
struct _pop_closure;

typedef struct _field_value
{
   const char          *value;
   struct _field_value *next;
} FieldValue;

typedef struct _header_field
{
   const char           *name;
   FieldValue           value;
   struct _header_field *next;
} HeaderField;


/**
 * @brief The POP message handler will call this function for every message on the server.
 *
 * @return 1 to continue receiving messages, 0 to signal library to stop sending messages.
 */
typedef int (*PopMessageUser)(struct _pop_closure *pop_closure,
                              const HeaderField *fields,
                              BuffControl *bc);

typedef enum recip_type
{
   RT_TO=0,
   RT_CC,
   RT_BCC,
   RT_SKIP
} RecipType;

typedef struct _recip_link
{
   enum recip_type    rtype;
   const char         *address;
   struct _recip_link *next;
   int                rcpt_status;
   int                enh_status;
} RecipLink;

typedef struct _smtp_args
{
   const char *host;
   const char *login;
   const char *password;
   int        port;
   int        use_tls;
} SmtpArgs;

typedef struct _pop_closure
{
   struct _comm_parcel *parcel;
   int                 message_count;
   int                 inbox_size;
   int                 message_index;
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

typedef void (*ServerReady)(struct _comm_parcel *parcel);
typedef void(*ReportEnvelopeRecipients)(struct _comm_parcel *parcel, RecipLink *rchain);
typedef int (*NextPOPMessageHeader)(struct _comm_parcel *parcel, struct _pop_closure *pop_closure );

typedef struct _comm_parcel
{
   /** [..] enclosed config file (if open) name of section containing connection details. */
   const char *account;

   /** Hook on which to attach application-specific data for access in callback functions. */
   void *data;

   /** Details for making the mail connection. */
   const char *host_url;
   int host_port;
   int starttls;

   /** account login credentials */
   const char *login;
   const char *password;

   /** Function pointer used after a session has been started and authorized. */
   ServerReady callback_func;

   /** Server communication conduit.  Provides either SSL or !SSL communication */
   STalker *stalker;

   /** Data transfer tracking maintained by STalker */
   int total_sent;
   int total_read;

   /** Message and logging flags and targets */
   int verbose;
   int quiet;
   const char *logfilepath;
   FILE *logfile;

   /** SMTP operations variables */
   const char *from;   // from field in SMTP envelope
   SmtpCaps caps;      // SMTP capabilities as reported by EHLO response
   ReportEnvelopeRecipients report_recipients;

   /** POP operations variables */
   int pop_reader;
   PopMessageUser pop_message_receiver;

} MParcel;


/** Public functions, all should start with mcb_ */

void mcb_advise_message(const MParcel *mp, ...);
void mcb_log_message(const MParcel *mp, ...);

int mcb_send_unlined_data(MParcel *mp, const char *str);
int mcb_send_data_endline(MParcel *mp);

int mcb_send_data(MParcel *mp, ...);
int mcb_send_line(MParcel *mp, const char *line, int line_data);
int mcb_recv_data(MParcel *mp, char *buffer, int len);

int mcb_digits_in_base(int value, int base);
int mcb_itoa_buff(int value, int base, char *buffer, int buffer_len);

size_t mcb_talker_reader(void *stalker, char *buffer, int buffer_len);

/** Mnemonic function to discern POP flag */
int mcb_is_opening_smtp(const MParcel *parcel) { return !parcel->pop_reader; }

void mcb_parse_header_line(const char *buffer,
                           const char *end,
                           const char **name,
                           int *name_len,
                           const char **value,
                           int *value_len);

int mcb_greet_smtp_server(MParcel *parcel);
int mcb_authorize_smtp_session(MParcel *parcel);
void mcb_quit_smtp_server(MParcel *parcel);

void mcb_greet_pop_server(MParcel *parcel);

void mcb_prepare_talker(MParcel *parcel, ServerReady talker_user);


typedef int (*IsEndEmailMessage)(const char *line, int line_len);

void mcb_send_email_new(MParcel *parcel,
                        RecipLink  *recipients,
                        const HeaderField *headers,
                        BuffControl *bc,
                        IsEndEmailMessage is_end_of_email);





#endif  // MAILCB_H
