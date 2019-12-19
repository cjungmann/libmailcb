#ifndef MAILCB_INTERNAL_H
#define MAILCB_INTERNAL_H

#include <sys/types.h>

#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/bio.h>

#include "socktalk.h"
#include "mailcb.h"

/** Functions that support establishing a connection. */
void log_ssl_error(MParcel *parcel, const SSL *ssl, int ret);
int get_connected_socket(const char *host_url, int port);
void open_ssl(MParcel *parcel, int socket_handle, ServerReady talker_user);


/** SMTP server access functions */
void initialize_smtp_session(MParcel *parcel);
void parse_smtp_capability_response(MParcel *parcel, const char *line, int line_len);
void parse_smtp_greeting_response(MParcel *parcel, const char *buffer, int buffer_len);
int send_envelope(MParcel *parcel, const char **recipients);
int send_headers(MParcel *parcel, const char **recipients, const char **headers);

/** POP server access functions */

int judge_pop_response(MParcel *parcel, const char *buffer, int len);
void parse_pop_stat(const char *buffer, int *count, int *inbox_size);

int parse_header_field(const char *start,
                       const char *end_of_buffer,
                       const char **tag,
                       int *tag_len,
                       const char **value,
                       int *value_len);

void copy_trimmed_email_field_value(char *target, const char *source, int source_len);
int send_pop_message_header(PopClosure *popc);

#endif
