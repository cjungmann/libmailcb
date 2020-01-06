#ifndef SOCKTALK_H
#define SOCKTALK_H

#include <sys/types.h>

#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/bio.h>

struct _stalker;

typedef int (*SockWriter)(const struct _stalker*, const void *data, int data_len);
typedef int (*SockReader)(const struct _stalker*, void *buffer, int buff_len);


/**
 * @brief Read *str to the next \r\n, setting output parameters *status **line, and *line_len.
 *
 * Use this function to parse the data returned from a SMTP server.  Use this
 * function to walk through the status and print or save the reply messages.
 *
 * View code for function dump_status_reply() for a usage example.
 * ~~~
 */
int walk_status_reply(const char *str, int *status, const char** line, int *line_len);

/**
 * @brief Debugging function that also illustrates simple use of walk_status_reply().
 */
void dump_status_reply(const char *buffer, int buffer_len);

/**
 * @brief Searches reply buffer for error messages, which are logged.
 *
 * @return Number of errors encountered.  (0 for no errors, duh.)
 */
int log_status_reply_errors(const char *buffer, int buffer_len);


int stk_sock_talker(const struct _stalker* talker, const void *data, int data_len);
int stk_ssl_talker(const struct _stalker* talker, const void *data, int data_len);

int stk_sock_reader(const struct _stalker* talker, void *buffer, int buff_len);
int stk_ssl_reader(const struct _stalker* talker, void *buffer, int buff_len);

/**
 * @brief Linked-list structure for preserving results of a socket read.
 */
typedef struct _status_line
{
   int  status;
   const char *message;
   struct _status_line *next;
} Status_Line;


typedef struct _stalker
{
   SSL*       ssl_handle;       // pointer to socket handle OR SSH structure
   int        socket_handle;
   SockWriter writer;
   SockReader reader;
} STalker;

/** STalker initialization functions to prepare STalker to call send_line, recv_line. */
void init_ssl_talker(struct _stalker* talker, SSL* ssl);
void init_sock_talker(struct _stalker* talker, int socket);


/**
 * Functions that actually read or write using the STalker object.
 */
size_t stk_simple_send_line(const struct _stalker* talker, const char *data, int data_len);
size_t stk_simple_send_unlined(const struct _stalker* talker, const char *data, int data_len);
size_t stk_vsend_line(const struct _stalker* talker, va_list args);
size_t stk_send_line(const struct _stalker* talker, ...);
size_t stk_recv_line(const struct _stalker* talker, void *buffer, int buff_len);
/** Send text like std_send_line, read and check response before returning. */
int stk_send_recv_line(const struct _stalker *talker, ...);

/**
 * @brief Given a chain of Status_Line, return 1 if a given message can be found, 0 otherwise.
 */
int seek_status_message(const Status_Line* sl, const char *value);

/**
 * @brief Print each link of a Status_Line chain.  Mostly for debugging.
 */
void show_status_chain(const Status_Line *ls);

#endif
