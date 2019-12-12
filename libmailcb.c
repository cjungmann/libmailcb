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

/**
 * @brief Writes arguments (const char*s following MParcel*, terminated by NULL)
 *        only if MParcel::verbose is true.
 */
void advise_message(const MParcel *mp, ...)
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
void log_message(const MParcel *mp, ...)
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

int send_data(MParcel *mp, ...)
{
   int bytes_sent = 0;
   va_list ap;
   va_start(ap, mp);
   
   mp->total_sent += bytes_sent = stk_vsend_line(mp->stalker, ap);

   va_end(ap);

   return bytes_sent;
}

int recv_data(MParcel *mp, char *buffer, int len)
{
   int bytes_read;
   mp->total_read += bytes_read =stk_recv_line(mp->stalker, buffer, len);
   return bytes_read;
}

int digits_in_base(int value, int base)
{
   int count = 0;
   while (value > 0)
   {
      ++count;
      value /= base;
   }

   return count;
}

int itoa_buff(int value, int base, char *buffer, int buffer_len)
{
   int output_length = digits_in_base(value, base);

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

void parse_capability_response(MParcel *parcel, const char *line, int line_len)
{
   const CapString *ptr = capstrings;
   while (ptr < capstring_end)
   {
      if (0 == strncmp(line, ptr->str, ptr->len))
         (*ptr->set_cap)(parcel, line, ptr->len);

      ++ptr;
   }
}

void parse_greeting_response(MParcel *parcel, const char *buffer, int buffer_len)
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
                  parse_capability_response(parcel, line, line_len);
            }

            ptr += advance_chars;
            break;
      }
   }
}

int get_connected_socket(const char *host_url, int port)
{
   struct addrinfo hints;
   struct addrinfo *ai_chain, *rp;

   int exit_value;
   int open_socket, temp_socket = -1;

   int port_buffer_len = digits_in_base(port, 10) + 1;
   char *port_buffer = (char*)alloca(port_buffer_len);
   if (itoa_buff(port, 10, port_buffer, port_buffer_len))
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
   }
   return open_socket;
}

int greet_server(MParcel *parcel, int socket_handle)
{
   int reply_status;
   int bytes_read;
   char buffer[1024];

   const char *host = parcel->host_url;

   STalker stalker;
   STalker *pstk = &stalker;
   init_sock_talker(pstk, socket_handle);

   // mparcel needs to know how to talk to the server:
   parcel->stalker = &stalker;

   // read response from socket connection?  i don't know why,
   // but we need to read the response before getting anything.
   bytes_read = recv_data(parcel, buffer, sizeof(buffer));

   advise_message(parcel, "about to greet server.", NULL);

   send_data(parcel, "EHLO ", host, NULL);
   bytes_read = recv_data(parcel, buffer, sizeof(buffer));
   parse_greeting_response(parcel, buffer, bytes_read);

   // if the profile asks for starttls and the server offers starttls, do it.
   if (parcel->starttls != 0 && get_starttls(parcel))
   {
      send_data(parcel, "STARTTLS", NULL);
      bytes_read = recv_data(parcel, buffer, sizeof(buffer));
      reply_status = atoi(buffer);

      if (reply_status >= 200 && reply_status < 300)
         start_ssl(parcel, socket_handle);
      else if (authorize_session(parcel))
      {
         // Send execution back to the caller:
         notify_mailer(parcel);
      }
   }
   else
   {
      printf("expected starttls in :\n[44;1m%.*s[m\n", bytes_read, buffer);
      advise_message(parcel, "proceeding without starttls.", NULL);
   }

   return 0;
}

void start_ssl(MParcel *parcel, int socket_handle)
{
   int bytes_read;
   STalker *pstk = parcel->stalker;
   const char *host = parcel->host_url;

   char buffer[1024];

   const SSL_METHOD *method;
   SSL_CTX *context;
   SSL *ssl;
   int connect_outcome;

   OpenSSL_add_all_algorithms();
   /* err_load_bio_strings(); */
   ERR_load_crypto_strings();
   SSL_load_error_strings();

   /* openssl_config(null); */

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
               STalker talker, *old_talker = parcel->stalker;
               init_ssl_talker(&talker, ssl);

               parcel->stalker = pstk = &talker;

               advise_message(parcel, "About to resend EHLO to get authorization information.", NULL);
               send_data(parcel, "EHLO ", host, NULL);
               bytes_read = recv_data(parcel, buffer, sizeof(buffer));
               parse_greeting_response(parcel, buffer, bytes_read);

               advise_message(parcel, "ssl protocol initialized.", NULL);

               if (authorize_session(parcel))
               {
                  // Send execution back to the caller:
                  notify_mailer(parcel);
               }

               // Restore previous STalker for when the SSL session is abandoned.
               // I would have put it after SSL_free(), but that reverses the SSL_new()
               // allocation rather than the connection.  This may be the wrong
               // thing, but it seems right now.
               parcel->stalker = old_talker;
            }
            else if (connect_outcome == 0)
               // failed with controlled shutdown
               log_message(parcel, "ssl connection failed and was cleaned up.", NULL);
            else
            {
               log_message(parcel, "ssl connection failed and aborted.", NULL);
               /* present_ssl_error(ssl_get_error(ssl, connect_outcome)); */
               ERR_print_errors_fp(parcel->logfile);
            }

            SSL_free(ssl);
         }
         else  // failed to get an ssl
         {
            log_message(parcel, "failed to get an ssl object.", NULL);
            ERR_print_errors_fp(parcel->logfile);
         }

         SSL_CTX_free(context);
      }
      else // failed to get a context
      {
         log_message(parcel, "Failed to get an SSL context.", NULL);
         ERR_print_errors_fp(parcel->logfile);
      }
   }
   else
      log_message(parcel, "Failed to get an SSL method.", NULL);
}

void message_auth_prompts(MParcel *parcel, const char *buffer, int len)
{
   printf("[34;1m%s[m with %d characters\n", buffer, len);

   int declen = c64_decode_chars_needed(len-4);
   char *tbuff = (char*)alloca(declen+1);

   c64_decode_to_buffer(&buffer[4], tbuff, declen+1);
   tbuff[declen] = '\0';

   advise_message(parcel, "Server responds: \"", tbuff, "\"", NULL);
}

int authorize_session(MParcel *parcel)
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
      /* send_data(parcel, "AUTH ", auth_type, NULL); */
      send_data(parcel, "AUTH LOGIN", NULL);
      bytes_received = recv_data(parcel, buffer, sizeof(buffer));
      buffer[bytes_received] = '\0';
      message_auth_prompts(parcel, buffer, bytes_received);
      reply_status = atoi(buffer);
      if (reply_status >= 300 && reply_status < 400)
      {
         c64_encode_to_buffer(login, strlen(login), (uint32_t*)&buffer, sizeof(buffer));
         advise_message(parcel,
                        "Sending user name, ",
                        login,
                        ", encoded as ",
                        buffer,
                        ", to the server.",
                        NULL);

         send_data(parcel, buffer, NULL);
         bytes_received = recv_data(parcel, buffer, sizeof(buffer));
         buffer[bytes_received] = '\0';
         message_auth_prompts(parcel, buffer, bytes_received);
         reply_status = atoi(buffer);
         if (reply_status >= 300 && reply_status < 400)
         {
            c64_encode_to_buffer(password, strlen(password), (uint32_t*)&buffer, sizeof(buffer));
            advise_message(parcel,
                           "Sending password, ",
                           password,
                           ", encoded as ",
                           buffer,
                           ", to the server.",
                           NULL);

            send_data(parcel, buffer, NULL);
            bytes_received = recv_data(parcel, buffer, sizeof(buffer));
            buffer[bytes_received] = '\0';
            reply_status = atoi(buffer);
            if (reply_status >= 200 && reply_status < 300)
               return 1;
            else
               log_message(parcel,
                           "For login name, ",
                           login,
                           ", the password, ",
                           password,
                           ", was not accepted by the server.",
                           " (",
                           buffer,
                           ")",
                           NULL);


         }
         else
            log_message(parcel,
                        "Login name, ",
                        login,
                        ", not accepted by the server.",
                        " (",
                        buffer,
                        ")",
                        NULL);
      }
      else
         log_message(parcel,
                     "Authorization request failed with \"",
                     buffer,
                     "\"",
                     NULL);
   }
   else
      log_message(parcel, "mailcb only supports PLAIN and LOGIN authorization.", NULL);


   return 0;
}

void notify_mailer(MParcel *parcel)
{
   char buffer[512];

   if (parcel->callback_func)
      (*parcel->callback_func)(parcel);
   else
      log_message(parcel, "No callback function provided to continue emailing.", NULL);

   // Politely terminate connection with server
   send_data(parcel, "QUIT", NULL);
   recv_data(parcel, buffer, sizeof(buffer));

   advise_message(parcel, "SMTP server sendoff.", NULL);
}

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
               STalker talker;
               init_ssl_talker(&talker, ssl);
               parcel->stalker = &talker;
               (*talker_user)(parcel);
            }

            SSL_free(ssl);
         }
         else
            log_message(parcel, "Failed to create a new SSL instance.", NULL);

         SSL_CTX_free(context);
      }
      else
         log_message(parcel, "Failed to initiate an SSL context.", NULL);
   }
   else
      log_message(parcel, "Failed to find SSL client method.", NULL);
}

void prepare_talker(MParcel *parcel, ServerReady talker_user)
{
   const char *host = parcel->host_url;
   int         port = parcel->port;
   int         use_tls = parcel->starttls;

   int osocket = get_connected_socket(host, port);
   if (osocket)
   {
      STalker talker;

      parcel->stalker = pstk = &talker;

      if (use_tls)
      {
      }
      else
      {
         init_sock_talker(&talker, osocket);
         parcel->stalker = &talker;
         (*talker_user)(parcel);
      }
   }
}


/**
 * @brief Internal function for send_email() to send an email envelope.
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
   send_data(parcel, "MAIL FROM: <", parcel->user, ">", NULL);
   bytes_read = recv_data(parcel, buffer, sizeof(buffer));

   reply_status = atoi(buffer);
   if (reply_status >= 200 && reply_status < 300)
   {
      while (*ptr)
      {
         send_data(parcel, "RCPT TO: <", *ptr, ">", NULL);
         bytes_read = recv_data(parcel, buffer, sizeof(buffer));
         buffer[bytes_read] = '\0';
         reply_status = atoi(buffer);
         if (reply_status >= 200 && reply_status < 300)
            ++recipients_accepted;
         else
            log_message(parcel, "Recipient, ", *ptr, ", was turned down by the server, ", buffer,  NULL);

         ++ptr;
      }

      if (recipients_accepted)
      {
         send_data(parcel, "DATA", NULL);
         bytes_read = recv_data(parcel, buffer, sizeof(buffer));
         reply_status = atoi(buffer);
         if (reply_status >= 300 && reply_status < 400)
            return 1;
         else
         {
            buffer[bytes_read] = '\0';
            log_message(parcel, "Envelope transmission failed, \"", buffer, "\"", NULL);
         }
      }
      else
         log_message(parcel, "Emailing aborted for lack of approved recipients.", NULL);
   }
   else
   {
      log_message(parcel,
                  "From field (",
                  parcel->user,
                  ") of SMTP envelope caused an error,\"",
                  buffer,
                  "\"",
                  NULL);
   }
   
   return 0;
}

/**
 * @brief Internal function for send_email() to send email headers.
 */
int send_headers(MParcel *parcel, const char **recipients, const char **headers)
{
   if (!recipients)
      return 0;

   const char **ptr = recipients;

   send_data(parcel, "From: ", parcel->user, NULL);

   // Send all the recipients
   while (*ptr)
   {
      send_data(parcel, "To: ", *ptr, NULL);
      ++ptr;
   }

   // Send all the headers
   ptr = headers;
   while (*ptr)
   {
      send_data(parcel, *ptr, NULL);
      ++ptr;
   }

   // Send blank line to terminate headers
   send_data(parcel, "", NULL);

   return 1;
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
void send_email(MParcel *parcel,
                const char **recipients,
                const char **headers,
                const char *msg)
{
   char buffer[1024];
   int bytes_read;
   int reply_status;

   if (send_envelope(parcel, recipients))
   {
      advise_message(parcel, "Server accepted the envelope.", NULL);
 
      if (send_headers(parcel, recipients, headers))
      {
         advise_message(parcel, "Server accepted the headers.", NULL);
 
         send_data(parcel, msg, NULL);
         send_data(parcel, ".", NULL);

         bytes_read = recv_data(parcel, buffer, sizeof(buffer));
         if (bytes_read > 0)
         {
            reply_status = atoi(buffer);
            if (reply_status >=200 && reply_status < 300)
               advise_message(parcel, "Message was sent to ", *recipients, ".", NULL);
            else
            {
               buffer[bytes_read] = '\0';
               log_message(parcel,
                           "The message to ",
                           *recipients,
                           " failed, saying \"",
                           buffer,
                           "\"",
                           NULL);
            }
         }
         else
            log_message(parcel, "The server failed to respond.", NULL);
      }
   }

}

