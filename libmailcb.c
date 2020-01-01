#include <code64.h>      // for encoding username and password

#include <netdb.h>       // For getaddrinfo() and supporting structures
#include <arpa/inet.h>   // Functions that convert addrinfo member values.
/* #include <netinet/in.h>  // conversion from addr (not working, not using) */

#include <string.h>      // for memset()
#include <assert.h>
#include <unistd.h>      // for close();
#include <stdarg.h>      // for va_args in advise() and log()

#include "socktalk.h"
#include "mailcb.h"

#include "commparcel.c"
#include "mailcb_internal.h"

CapString capstrings[] = {
   /* {"AUTH",                 4, set_auth}, */
   {"SIZE",                 4, set_size},
   {"STARTTLS",             8, set_starttls},
   {"ENHANCEDSTATUSCODES", 19, set_enhancedstatuscodes},
   {"8BITMIME",             8, set_8bitmime},
   {"7BITMIME",             8, set_7bitmime},
   {"PIPELINING",          10, set_pipelining},
   {"SMTPUTF8",             8, set_smtputf8},
   {"CHUNKING",             8, set_chunking}
};

int capstrings_count = sizeof(capstrings) / sizeof(CapString);
const CapString *capstring_end = &capstrings[sizeof(capstrings) / sizeof(CapString)];

/**
 * @brief Creates a readable message from SSL_get_error() for logging an error.
 */
void log_ssl_error(MParcel *parcel, const SSL *ssl, int ret)
{
   int error = SSL_get_error(ssl, ret);
   const char *msg = NULL;
   switch(error)
   {
      case SSL_ERROR_NONE:
         msg = "SSL_ERROR_NONE";
         break;

      case SSL_ERROR_ZERO_RETURN:
         msg = "SSL_ERROR_ZERO_RETURN";
         break;
      case SSL_ERROR_WANT_READ:
         msg = "SSL_ERROR_WANT_READ";
         break;
      case SSL_ERROR_WANT_WRITE:
         msg = "SSL_ERROR_WANT_WRITE";
         break;
      case SSL_ERROR_WANT_CONNECT:
         msg = "SSL_ERROR_WANT_CONNECT";
         break;
      case SSL_ERROR_WANT_ACCEPT:
         msg = "SSL_ERROR_WANT_ACCEPT";
         break;
      case SSL_ERROR_WANT_X509_LOOKUP:
         msg = "SSL_ERROR_WANT_X509_LOOKUP";
         break;
      case SSL_ERROR_SYSCALL:
         msg = "SSL_ERROR_SYSCALL";
         break;
      case SSL_ERROR_SSL:
         msg = "SSL_ERROR_SSL";
         break;
      default:
         msg = NULL;
   }

   if (msg)
      mcb_log_message(parcel, "SSL failure: ", msg, NULL);
   else
   {
      int dlen = mcb_digits_in_base(error, 10);
      char *buffer = (char*)alloca(dlen);
      mcb_itoa_buff(error, 10, buffer, dlen);

      mcb_log_message(parcel, "Unrecognized SSL_get_error() response, \"", msg, "\"",  NULL);
   }
}

/**
 * @brief Open a socket to the given host on the specified port.
 *
 * Unlike other functions in this library, this function **does not**
 * clean up after itself. A successfully calling this function must
 * explicitely close the socket handle.
 */
int get_connected_socket(const char *host_url, int port)
{
   struct addrinfo hints;
   struct addrinfo *ai_chain, *rp;

   int exit_value;
   int open_socket = -1, temp_socket = -1;

   int port_buffer_len = mcb_digits_in_base(port, 10) + 1;
   char *port_buffer = (char*)alloca(port_buffer_len);
   if (mcb_itoa_buff(port, 10, port_buffer, port_buffer_len))
   {
      memset((void*)&hints, 0, sizeof(struct addrinfo));
      hints.ai_family = AF_INET;
      hints.ai_socktype = SOCK_STREAM;
      hints.ai_flags = AI_CANONNAME;
      hints.ai_protocol = IPPROTO_TCP;

      exit_value = getaddrinfo(host_url, port_buffer, &hints, &ai_chain);

      if (exit_value==0)
      {
         rp = ai_chain;
         while (rp)
         {
            if ((rp->ai_family == PF_INET || rp->ai_family == PF_INET6)
                && rp->ai_socktype == SOCK_STREAM
                && rp->ai_protocol == IPPROTO_TCP)
            {
               temp_socket = socket(rp->ai_family,
                                    rp->ai_socktype,
                                    rp->ai_protocol);

               break;
            }

            rp = rp->ai_next;
         }

         if (temp_socket >= 0)
         {
            if (0 == connect(temp_socket, rp->ai_addr, rp->ai_addrlen))
               open_socket = temp_socket;
            else
               close(temp_socket);
         }

         freeaddrinfo(ai_chain);
      }
      else // exit_value != 0 getaddrinfo call failed
      {
         fprintf(stderr,
                 "Failed to open socket for %s : %d: %s.\n",
                 host_url,
                 port,
                 gai_strerror(exit_value));
      }
   }
   return open_socket;
}

/**
 * @brief Gets a SSL handle for an open socket, calling the MParcel::callback_func
 *        function pointer when it's SSL handle is working.
 *
 * This function automatically resends the EHLO request to update
 * the MParcel::SmtpCaps structure.  That ensures that the
 * talker_user function gets an accurate indication of the
 * server's capabilities.
 *
 * We have to reaquire the caps because one server, I think it
 * was mail.privateemail.com wouldn't allow STARTTLS when the
 * STARTTLS capability hadn't been advertised, so that meant
 * I couldn't simply check the use_tls flag and then call for
 * STARTTLS.  GMail seems to work similarly, though not identically.
 */
void open_ssl(MParcel *parcel, int socket_handle, ServerReady talker_user)
{
   const SSL_METHOD *method;
   SSL_CTX *context;
   SSL *ssl;
   int connect_outcome;

   OpenSSL_add_all_algorithms();
   /* err_load_bio_strings(); */
   ERR_load_crypto_strings();
   SSL_load_error_strings();

   /* openssl_config(null); */

   mcb_advise_message(parcel, "About to open SSL", NULL);

   SSL_library_init();

   method = SSLv23_client_method();
   if (method)
   {
      context = SSL_CTX_new(method);

      if (context)
      {
         // following two not included in most recent example code i found.
         // it may be appropriate to uncomment these lines as i learn more.
         /* ssl_ctx_set_verify(context, ssl_verify_peer, null); */
         /* ssl_ctx_set_verify_depth(context, 4); */

         // we could set some flags, but i'm not doing it until i need to and i understand 'em
         /* const long ctx_flags = ssl_op_no_sslv2 | ssl_op_no_sslv3 | ssl_op_no_compression; */
         /* ssl_ctx_set_options(context, ctx_flags); */
         SSL_CTX_set_options(context, SSL_OP_NO_SSLv2);

         ssl = SSL_new(context);
         if (ssl)
         {
            SSL_set_fd(ssl, socket_handle);

            connect_outcome = SSL_connect(ssl);

            if (connect_outcome == 1)
            {
               STalker *old_talker = parcel->stalker;

               STalker talker;
               init_ssl_talker(&talker, ssl);
               parcel->stalker = &talker;

               // Gmail advertises different capabilities after SSL initialization:
               if (mcb_is_opening_smtp(parcel))
                  initialize_smtp_session(parcel);

               (*talker_user)(parcel);

               parcel->stalker = old_talker;
            }
            else if (connect_outcome == 0)
            {
               // failed with controlled shutdown
               log_ssl_error(parcel, ssl, connect_outcome);
               mcb_log_message(parcel, "ssl connection failed and was cleaned up.", NULL);
            }
            else
            {
               log_ssl_error(parcel, ssl, connect_outcome);
               mcb_log_message(parcel, "ssl connection failed and aborted.", NULL);
               mcb_log_message(parcel, "host: ", parcel->host_url, ", from: ", parcel->from, NULL);
            }

            SSL_free(ssl);
         }
         else
            mcb_log_message(parcel, "Failed to create a new SSL instance.", NULL);

         SSL_CTX_free(context);
      }
      else
         mcb_log_message(parcel, "Failed to initiate an SSL context.", NULL);
   }
   else
      mcb_log_message(parcel, "Failed to find SSL client method.", NULL);
}

/**
 * @brief Send EHLO and process the response to the MParcel Caps member.
 */
void initialize_smtp_session(MParcel *parcel)
{
   char buffer[1024];
   int bytes_read;

   mcb_send_data(parcel, "EHLO ", parcel->host_url, NULL);
   bytes_read = mcb_recv_data(parcel, buffer, sizeof(buffer));
   parse_smtp_greeting_response(parcel, buffer, bytes_read);
}

/**
 * @brief Used by parse_smtp_greeting_response() to interpret the EHLO response.
 */
void parse_smtp_capability_response(MParcel *parcel, const char *line, int line_len)
{
   const CapString *ptr = capstrings;
   while (ptr < capstring_end)
   {
      if (0 == strncmp(line, ptr->str, ptr->len))
         (*ptr->set_cap)(parcel, line, ptr->len);

      ++ptr;
   }
}

/**
 * @brief Set the MParcel::SmtpCaps with the SMTP server response.
 *
 * The buffer should contain the response from the SMTP after sending
 * an EHLO <host name> request.
 */
void parse_smtp_greeting_response(MParcel *parcel, const char *buffer, int buffer_len)
{
   // walk_status_reply variables:
   int status;
   const char *line;
   int line_len;
   int advance_chars;

   // progress variables
   const char *ptr = buffer;
   const char *end = buffer + buffer_len;

   clear_smtp_caps(parcel);

   while (ptr < end)
   {
      advance_chars = walk_status_reply(ptr, &status, &line, &line_len);
      switch(advance_chars)
      {
         case -1:
            fprintf(parcel->logfile, "Error processing replys from \"%s\"\n", buffer);
         case 0:
            ptr = end;  // set ptr to break loop
            break;
         default:
            if (status == 250)
            {
               if (0 == strncmp(line, "AUTH", 4))
                  set_auth(parcel, line, line_len);
               else
                  parse_smtp_capability_response(parcel, line, line_len);
            }

            ptr += advance_chars;
            break;
      }
   }
}

/**
 * @brief Internal function for mcb_send_email() to send an email envelope.
 *
 * @param recipients is an array of pointers to const char*, with a
 *                   final pointer to NULL to mark the end of the list.
 */
int send_envelope(MParcel *parcel, const char **recipients)
{
   if (!recipients)
      return 0;

   char buffer[1024];
   const char **ptr = recipients;
   int bytes_read;
   int recipients_accepted = 0;
   int reply_status;
   mcb_send_data(parcel, "MAIL FROM: <", parcel->from, ">", NULL);
   bytes_read = mcb_recv_data(parcel, buffer, sizeof(buffer));

   reply_status = atoi(buffer);
   if (reply_status >= 200 && reply_status < 300)
   {
      printf("env response: '%.*s'\n", bytes_read, buffer);

      while (*ptr)
      {
         mcb_send_data(parcel, "RCPT TO: <", *ptr, ">", NULL);
         bytes_read = mcb_recv_data(parcel, buffer, sizeof(buffer));
         buffer[bytes_read] = '\0';
         reply_status = atoi(buffer);
         if (reply_status >= 200 && reply_status < 300)
            ++recipients_accepted;
         else
            mcb_log_message(parcel, "Recipient, ", *ptr, ", was turned down by the server, ", buffer,  NULL);

         ++ptr;
      }

      if (recipients_accepted)
      {
         mcb_send_data(parcel, "DATA", NULL);
         bytes_read = mcb_recv_data(parcel, buffer, sizeof(buffer));
         reply_status = atoi(buffer);
         if (reply_status >= 300 && reply_status < 400)
            return 1;
         else
         {
            buffer[bytes_read] = '\0';
            mcb_log_message(parcel, "Envelope transmission failed, \"", buffer, "\"", NULL);
         }
      }
      else
         mcb_log_message(parcel, "Emailing aborted for lack of approved recipients.", NULL);
   }
   else
   {
      mcb_log_message(parcel,
                  "From field (",
                  parcel->from,
                  ") of SMTP envelope caused an error,\"",
                  buffer,
                  "\"",
                  NULL);
   }
   
   return 0;
}

/**
 * @brief Internal function for mcb_send_email() to send email headers.
 */
int send_headers(MParcel *parcel, const char **recipients, const char **headers)
{
   if (!recipients)
      return 0;

   const char **ptr = recipients;

   mcb_send_data(parcel, "From: ", parcel->from, NULL);

   // Send all the recipients
   while (*ptr)
   {
      mcb_send_data(parcel, "To: ", *ptr, NULL);
      ++ptr;
   }

   // Send all the headers
   ptr = headers;
   while (*ptr)
   {
      mcb_send_data(parcel, *ptr, NULL);
      ++ptr;
   }

   // Send blank line to terminate headers
   mcb_send_data(parcel, "", NULL);

   return 1;
}

/**
 * @brief Returns 0 for error, 1 for success.
 *
 * The first character of a POP response indicates if the
 * operation succeeded or failed.  '+' indicates success,
 * like +OK.  '-' indicates failure.
 *
 * A POP error will be logged.
 */
int judge_pop_response(MParcel *parcel, const char *buffer, int len)
{
   if (buffer[0] == '+')
      return 1;
   else
      mcb_log_message(parcel, "POP server error: ", &buffer[1], NULL);

   return 0;
}

/**
 * @brief Interprets the response to the POP STAT request.
 *
 * Note that the results are returned in pointer arguments.
 */
void parse_pop_stat(const char *buffer, int *count, int *inbox_size)
{
   const char *ptr = buffer;
   *count = 0;
   *inbox_size = 0;

   while (!isdigit(*ptr))
      ++ptr;

   while (isdigit(*ptr))
   {
      *count *= 10;
      *count += *ptr - '0';
      ++ptr;
   }

   while (!isdigit(*ptr))
      ++ptr;

   while (isdigit(*ptr))
   {
      *inbox_size *= 10;
      *inbox_size += *ptr - '0';
      ++ptr;
   }
}

/**
 * @brief Identifies the start and length of the name and value values.
 *
 * Called by send_pop_message_header() to outsource the interpretation of a field in an email header
 *
 * The interpretation results are returned in pointer arguments of the function.
 *
 * The function returns the number of chars from the address of _*start_
 * to the beginning of the next header line.  See send_pop_message_header()
 * to better learn how to use this function.
 */ 
int parse_header_field(const char *start,
                       const char *end_of_buffer,
                       const char **tag,
                       int *tag_len,
                       const char **value,
                       int *value_len)
{
   *tag = *value = NULL;
   *tag_len = *value_len = 0;

   const char *end_of_field = NULL;
   const char *end_of_consideration = NULL;

   const char *ptr = start;

   // Find the end-of-field:
   while (ptr < end_of_buffer)
   {
      if (0 == strncmp(ptr,"\r\n",2))
      {
         // End of field if \r\n and a non-space character
         // introducing the next header field
         if (!isspace(*(ptr+2)))
         {
            end_of_field = ptr;

            // point to beginning of next line:
            end_of_consideration = ptr + 2;
            break;
         }
         else if (0 == strncmp(&ptr[2], "\r\n", 2))
         {
            end_of_field = ptr;

            // Point to end of buffer to end fields processing
            end_of_consideration = end_of_buffer;
            break;
         }
      }

      ++ptr;
   }

   // If can't find end-of-field, return character count to end-of-buffer: 
   if (! end_of_field)
      return (end_of_buffer - start);

   *tag = start;

   // If +OK, set tag_len but not value or value_len to
   // help the calling function move to the next line
   if (0 == strncmp(ptr, "+OK", 3))
   {
      *tag_len = end_of_field - *tag;
   }
   else
   {
      // ptr at end-of-field, return to beginning of line for char comparison:
      ptr = *tag;

      // Find the colon, which marks the end of the tag
      while (ptr < end_of_field && *ptr != ':')
         ++ptr;

      *tag_len = ptr - *tag;

      if (*ptr == ':')
      {
         // Trim spaces to find start of value.
         // Note different "while" form because the starting
         // colon is assured and is not a space, so we must
         // increment the pointer before checking if space.
         while (++ptr < end_of_field && isspace(*ptr))
            ;

         *value = ptr;

         *value_len = end_of_field - ptr;
      }
   }

   return end_of_consideration - start;
}

/**
 * @brief This function assumes that the size of the target is the
 *        same as the source.  The target may end up shorter than
 *        source if the source is a multi-line value, and the \r\n\s+
 *        characters will be replaced with a single \t to aid in
 *        interpreting the value (split on tabs for sublines).
 */       
void copy_trimmed_email_field_value(char *target, const char *source, int source_len)
{
   char *ptr_t = target;
   const char *ptr_s = source;
   const char *end_source = source + source_len;

   while (ptr_s < end_source)
   {
      // Compress \r\n\s+ to \t
      if (*ptr_s == '\r')
      {
         *ptr_t = '\t';
         ++ptr_t;

         while (isspace(*++ptr_s))
            ;
      }
      else
         *ptr_t++ = *ptr_s++;
   }
   *ptr_t = '\0';
}

/**
 * @brief Retrieves the headers, parsing them into discrete name/value pairs and sending to callback.
 */
int send_pop_message_header(PopClosure *popc)
{
   char buffer[1024];
   int bytes_read;

   HeaderField *head = NULL, *tail = NULL, *cur;

   const char *name, *value, *ptr, *line;
   int name_len, value_len;

   const char *end_of_buffer;
   char *work;

   int bytes_to_advance;

   // Borrow buffer to convert the integer to a string for the TOP command
   mcb_itoa_buff(popc->message_index+1, 10, buffer, sizeof(buffer));
   mcb_send_data(popc->parcel, "TOP ", buffer, " 0", NULL);

   while ((bytes_read = mcb_recv_data(popc->parcel, buffer, sizeof(buffer))) > 0)
   {
      end_of_buffer = &buffer[bytes_read];
      line = ptr = buffer;

      while (line < end_of_buffer)
      {
         bytes_to_advance = parse_header_field(line,
                                               end_of_buffer,
                                               &name,
                                               &name_len,
                                               &value,
                                               &value_len);

         if (!popc->message_confirmed)
         {
            if (*line == '-')
            {
               mcb_log_message(popc->parcel, "Unexpected failure for TOP: \"", line, "\"", NULL);
               goto abort_processing;
            }
            else if (*line != '+')
            {
               mcb_log_message(popc->parcel, "Unexpected confirmation line, \"", line, "\"", NULL);
            }

            popc->message_confirmed = 1;
         }

         if (name)
         {
            if (value)
            {
               cur = (HeaderField*)alloca(sizeof(HeaderField));
               memset(cur, 0, sizeof(HeaderField));

               work = (char*)alloca(name_len+1);
               memcpy(work, name, name_len);
               work[name_len] = '\0';

               cur->name = work;

               work = (char*)alloca(value_len);
               copy_trimmed_email_field_value(work, value, value_len);
               cur->value = work;

               if (tail)
               {
                  tail->next = cur;
                  tail = cur;
               }
               else
                  head = tail = cur;
            }
            else if (0 == strncmp(name, "+OK", 3))
            {
               ; // ignore status line
            }
            else  // Incomplete field, shift and continue reading
            {
               memmove(buffer, line, bytes_to_advance);
               bytes_read = mcb_recv_data(popc->parcel,
                                          &buffer[bytes_to_advance],
                                          sizeof(buffer)-bytes_to_advance);

               end_of_buffer = &buffer[bytes_read + bytes_to_advance];
               line = ptr = buffer;

               // Bypass update
               continue;
            }
         }

         line += bytes_to_advance;
      } // while (line < end_of_buffer)
   }  // while bytes_read > 0

   assert(popc->parcel->pop_message_receiver);
   return (*popc->parcel->pop_message_receiver)(popc, head);

  abort_processing:
   return 0;
}



/**
 * @brief Writes arguments (const char*s following MParcel*, terminated by NULL)
 *        only if MParcel::verbose is true.
 */
void mcb_advise_message(const MParcel *mp, ...)
{
   va_list ap;
   const char *str;

   if (mp->verbose)
   {
      FILE *msgfile = stdout;

      va_start(ap, mp);

      while((str = va_arg(ap, char*)))
         fputs(str, msgfile);

      fputc('\n', msgfile);

      va_end(ap);
   }
}

/**
 * @brief Writes arguments (const char*s following MParcel*, terminated by NULL)
 *        only if MParcel::quiet is NOT true.
 */
void mcb_log_message(const MParcel *mp, ...)
{
   va_list ap;
   const char *str;

   if (!mp->quiet)
   {
      FILE *msgfile = mp->logfile ? mp->logfile : stdout;
      va_start(ap, mp);

      while((str = va_arg(ap, char*)))
         fputs(str, msgfile);

      fputc('\n', msgfile);

      va_end(ap);
   }
}

int mcb_send_data(MParcel *mp, ...)
{
   int bytes_sent = 0;
   va_list ap;
   va_start(ap, mp);
   
   mp->total_sent += bytes_sent = stk_vsend_line(mp->stalker, ap);

   va_end(ap);

   return bytes_sent;
}

int mcb_recv_data(MParcel *mp, char *buffer, int len)
{
   int bytes_read;
   mp->total_read += bytes_read =stk_recv_line(mp->stalker, buffer, len);
   return bytes_read;
}

int mcb_digits_in_base(int value, int base)
{
   int count = 0;
   while (value > 0)
   {
      ++count;
      value /= base;
   }

   return count;
}

int mcb_itoa_buff(int value, int base, char *buffer, int buffer_len)
{
   int output_length = mcb_digits_in_base(value, base);

   if (output_length < buffer_len)
   {
      memset(buffer, 0, buffer_len);
      char *ptr = &buffer[output_length-1];

      while (value > 0)
      {
         *ptr = (value % base) + '0';
         --ptr;
         value /= base;
      }

      return 1;
   }
   else
      return 0;
}

/**
 * @brief Initialize connection with specified URL on specified port.  Initializes TLS if requested.
 *
 * This function opens a socket, the opens SSL if requested.  In either case, a STalker
 * object is initialized and returned to the caller through the MParcel pointer.
 */
void mcb_prepare_talker(MParcel *parcel, ServerReady talker_user)
{
   const char *host = parcel->host_url;
   int         port = parcel->host_port;

   char        buffer[1024];
   int         bytes_read;

   int osocket = get_connected_socket(host, port);
   if (osocket > 0)
   {
      mcb_advise_message(parcel, "Got an open socket.", NULL);

      STalker talker;
      init_sock_talker(&talker, osocket);
      parcel->stalker = &talker;

      if (mcb_is_opening_smtp(parcel))
      {
         bytes_read = mcb_recv_data(parcel, buffer, sizeof(buffer));
         fprintf(stderr, "Socket response: \"%.*s\".\n", bytes_read, buffer);

         initialize_smtp_session(parcel);
      }

      if (parcel->starttls)
      {
         if (parcel->caps.cap_starttls)
         {
            mcb_advise_message(parcel, "Starting TLS", NULL);

            mcb_send_data(parcel, "STARTTLS", NULL);
            bytes_read = mcb_recv_data(parcel, buffer, sizeof(buffer));
            buffer[bytes_read] = '\0';
            mcb_advise_message(parcel, buffer, NULL);
         }

         open_ssl(parcel, osocket, talker_user);
      }
      else
      {
         // Not using SSL/TLS
         (*talker_user)(parcel);
      }

      close(osocket);
   }
}

/**
 * @brief Initialize SMTP server conversation, submitting credentials if appropriate.
 *
 * @return 1 if success. Calling function must terminate the conversation with "QUIT" message to server.
 *         0 if failed.  Failure will terminate the conversation immediately,
 */
int mcb_greet_smtp_server(MParcel *parcel)
{
   char buffer[1024];
   int bytes_read;

   mcb_send_data(parcel, "EHLO ", parcel->host_url, NULL);
   bytes_read = mcb_recv_data(parcel, buffer, sizeof(buffer));
   parse_smtp_greeting_response(parcel, buffer, bytes_read);

   if (mcb_authorize_smtp_session(parcel))
      return 1;
   else
   {
      mcb_quit_smtp_server(parcel);
      return 0;
   }
}

/**
 * @brief Send account credentials to the SMTP server.
 */
int mcb_authorize_smtp_session(MParcel *parcel)
{
   char buffer[1024];
   int bytes_received;
   int reply_status;

   const char *login = parcel->login;
   const char *password = parcel->password;

   int use_plain = parcel->caps.cap_auth_plain;
   int use_login = parcel->caps.cap_auth_login;

   const char *auth_type = (use_plain?"PLAIN":(use_login?"LOGIN":NULL));

   // PLAIN accepts concatenated \0login\0password string (both prefixed with NULL character).
   // LOGIN accepts separate login and password submissions


   if (auth_type)
   {
      /* mcb_send_data(parcel, "AUTH ", auth_type, NULL); */
      mcb_send_data(parcel, "AUTH LOGIN", NULL);
      bytes_received = mcb_recv_data(parcel, buffer, sizeof(buffer));
      buffer[bytes_received] = '\0';

      // reply status in the 300 range (334) indicates
      // good so far, but need more inputx
      reply_status = atoi(buffer);
      if (reply_status >= 300 && reply_status < 400)
      {
         c64_encode_to_buffer(login, strlen(login), (uint32_t*)&buffer, sizeof(buffer));
         mcb_advise_message(parcel,
                        "Sending user name, ",
                        login,
                        ", encoded as ",
                        buffer,
                        ", to the server.",
                        NULL);

         mcb_send_data(parcel, buffer, NULL);
         bytes_received = mcb_recv_data(parcel, buffer, sizeof(buffer));
         buffer[bytes_received] = '\0';


         // reply status in the 300 range (334) indicates
         // good so far, but need more inputx
         reply_status = atoi(buffer);
         if (reply_status >= 300 && reply_status < 400)
         {
            c64_encode_to_buffer(password, strlen(password), (uint32_t*)&buffer, sizeof(buffer));
            mcb_advise_message(parcel,
                           "Sending password, encoded as ",
                           buffer,
                           ", to the server.",
                           NULL);

            mcb_send_data(parcel, buffer, NULL);
            bytes_received = mcb_recv_data(parcel, buffer, sizeof(buffer));
            buffer[bytes_received] = '\0';
            reply_status = atoi(buffer);
            if (reply_status >= 200 && reply_status < 300)
               return 1;
            else
               mcb_log_message(parcel,
                           "For login name, ",
                           login,
                           ", the password was not accepted by the server.",
                           " (",
                           buffer,
                           ")",
                           NULL);
         }
         else
            mcb_log_message(parcel,
                        "Login name, ",
                        login,
                        ", not accepted by the server.",
                        " (",
                        buffer,
                        ")",
                        NULL);
      }
      else
         mcb_log_message(parcel,
                     "Authorization request failed with \"",
                     buffer,
                     "\"",
                     NULL);
   }
   else
      mcb_log_message(parcel, "mailcb only supports PLAIN and LOGIN authorization.", NULL);

   return 0;
}

/**
 * @brief Terminate SMTP server conversation (socket and/or SSL handle remain open).
 */
void mcb_quit_smtp_server(MParcel *parcel)
{
   char buffer[1024];
   mcb_send_data(parcel, "QUIT", NULL);
   mcb_recv_data(parcel, buffer, sizeof(buffer));

   mcb_advise_message(parcel, "SMTP server sendoff.", NULL);
}

void mcb_greet_pop_server(MParcel *parcel)
{
   char buffer[1024];
   int bytes_read;

   // read response from socket connection?  i don't know why,
   // but we need to read the response before getting anything.
   // Usually, this will be somethiing like "+OK Dovecot ready."
   bytes_read = mcb_recv_data(parcel, buffer, sizeof(buffer));

   mcb_send_data(parcel, "USER ", parcel->login, NULL);
   bytes_read = mcb_recv_data(parcel, buffer, sizeof(buffer));
   buffer[bytes_read] = '\0';
   
   if (judge_pop_response(parcel, buffer, bytes_read))
   {
      mcb_send_data(parcel, "PASS ", parcel->password, NULL);
      bytes_read = mcb_recv_data(parcel, buffer, sizeof(buffer));
      buffer[bytes_read] = '\0';
      if (judge_pop_response(parcel, buffer, bytes_read))
      {
         mcb_send_data(parcel, "STAT", NULL);
         bytes_read = mcb_recv_data(parcel, buffer, sizeof(buffer));
         buffer[bytes_read] = '\0';
         if (judge_pop_response(parcel, buffer, bytes_read))
         {
            PopClosure popc = { parcel, 0, 0, 0 };
            parse_pop_stat(buffer, &popc.message_count, &popc.inbox_size);

            while (popc.message_index < popc.message_count)
            {
               mcb_advise_message(parcel, "Processing an email.", NULL);
               popc.message_confirmed = 0;
               if (send_pop_message_header(&popc))
                  ++popc.message_index;
               else
                  break;
            }

            printf("POP server has %d messages, for a total of %d total bytes.\n",
                   popc.message_count,
                   popc.inbox_size);
         }
      }
   }
}

/**
 * Send an email through an established connection.
 *
 * @param recipients Null-terminated list of pointers to recipients
 *                   that will be included in the envelope (RCVT TO:)
 * @param headers    Null-terminated list of email headers to be
 *                   sent before the message.
 * @param msg        Text of message to be sent.
 */
void mcb_send_email(MParcel *parcel,
                    const char **recipients,
                    const char **headers,
                    const char *msg)
{
   char buffer[1024];
   int bytes_read;
   int reply_status;

   if (send_envelope(parcel, recipients))
   {
      mcb_advise_message(parcel, "Server accepted the envelope.", NULL);
 
      if (send_headers(parcel, recipients, headers))
      {
         mcb_advise_message(parcel, "Server accepted the headers.", NULL);
 
         mcb_send_data(parcel, msg, NULL);
         mcb_send_data(parcel, ".", NULL);

         bytes_read = mcb_recv_data(parcel, buffer, sizeof(buffer));
         if (bytes_read > 0)
         {
            reply_status = atoi(buffer);
            if (reply_status >=200 && reply_status < 300)
               mcb_advise_message(parcel, "Message was sent to ", *recipients, ".", NULL);
            else
            {
               buffer[bytes_read] = '\0';
               mcb_log_message(parcel,
                           "The message to ",
                           *recipients,
                           " failed, saying \"",
                           buffer,
                           "\"",
                           NULL);
            }
         }
         else
            mcb_log_message(parcel, "The server failed to respond.", NULL);
      }
   }
}

