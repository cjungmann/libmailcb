#include <code64.h>      // for encoding username and password

#include <netdb.h>       // For getaddrinfo() and supporting structures
#include <arpa/inet.h>   // Functions that convert addrinfo member values.
/* #include <netinet/in.h>  // conversion from addr (not working, not using) */

#include <string.h>      // for memset()
#include <assert.h>
#include <unistd.h>      // for close();
#include <stdarg.h>      // for va_args in advise() and log()
#include <ctype.h>       // for isspace()

#include "socktalk.h"
#include "mailcb.h"
#include "commparcel.h"

#include "mailcb_internal.h"

/**
 * @brief Convert uint8 value to two hex chars. Used by mcb_make_guid().
 *
 * The _*target_ parameter must point to memory large enough
 * to contain the two hex chars that will be the result of
 * the conversion.  No checking is possible.
 */
void hexify_digit(char *target, uint8_t value)
{
   int low16 = value % 16;
   value /= 16;

   *target++ = value<10 ? ('0' + value) : ((value-10) + 'a');
   *target = low16<10 ? ('0' + low16) : ((low16-10) + 'a');
}

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
                  smtp_initialize_session(parcel);

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
 * @brief Judges SMTP server response to RCPT_TO request.
 */
int rcpt_status_ok(const RecipLink *rlink)
{
   return rlink->rcpt_status >= 200 && rlink->rcpt_status < 300;
}


/**
 * @brief Convenience function to add context to POP error log.
 */
void log_pop_closure_message(const PopClosure *pc, const char *msg)
{
   char buffer[128];
   sprintf(buffer, "At message %d of %d, ", pc->message_index, pc->message_count);
   mcb_log_message(pc->parcel, buffer, msg, NULL);
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

int send_pop_message_header(PopClosure *popc)
{
   char buffer[1024];
   memset(buffer, 0, sizeof(buffer));

   // We must send a request first because init_buff_control()
   // makes an initial call to read the socket, which is empty
   // until we send a TOP command.
   mcb_itoa_buff(popc->message_index+1, 10, buffer, sizeof(buffer));
   mcb_send_data(popc->parcel, "TOP ", buffer, " 0", NULL);

   BuffControl bc;
   init_buff_control(&bc,
                     buffer, 
                     sizeof(buffer),
                     mcb_talker_reader,
                     (void*)popc->parcel->stalker);

   PopMessageUser pmu = popc->parcel->pop_message_receiver;

   // Variables whose pointers are passed to get_bc_line()
   const char *line;
   int line_len;

   // Variables whose pointers are passed to mcb_parse_header_line()
   const char *name, *value;
   int name_len, value_len;

   // non-const placeholders in which strings can be initialized
   char *tname, *tvalue;

   // Header Field Chain links:
   HeaderField *froot = NULL, *ftail = NULL, *fcur = NULL;
   FieldValue *vtail = NULL, *vcur = NULL;

  // We haven't yet read the response to the TOP message.
   int message_confirmed = 0;

   while(bc_get_next_line(&bc, &line, &line_len))
   {
      // We're only collecting header fields, so break
      // out if it's a single character,  '.', line.
      if (line_len == 1 && *line == '.')
         goto execute_pop_callback;

      // Process first line after TOP message sent:
      if (!message_confirmed)
      {
         // We are abandoning the message, so we can trash
         // the buffer in order to send the message.
         if (*line == '-')
         {
            log_pop_closure_message(popc,
                                    "Unexpected failure response ('-') after TOP request.");
            goto purge_response_return_error;
         }
         else if (*line != '+')
         {
            log_pop_closure_message(popc,
                                    "Unexpected response prefix (not '-' or '+') after TOP request.");
            goto purge_response_return_error;
         }
          
         message_confirmed = 1;
         continue;
      }
      else  // message_confirmed
      {
         mcb_parse_header_line(line, &line[line_len], &name, &name_len, &value, &value_len);

         if (name_len)
         {
            // Create and initialize an empty Headerfield
            fcur = (HeaderField*)alloca(sizeof(HeaderField));
            memset(fcur, 0, sizeof(HeaderField));

            // Make non-const string to initialize its value
            tname = (char*)alloca(name_len+1);
            memcpy(tname, name, name_len);
            tname[name_len] = '\0';

            // Attach non-const char* to const char* struct member:
            fcur->name = tname;

            // Attach new link to chain (or to root)
            if (ftail)
            {
               ftail->next = fcur;
               ftail = fcur;
            }
            else
               froot = ftail = fcur;

            // Establishing a new field means previous value chain is invalid:
            vcur = vtail = NULL;
         }

         if (value_len)
         {
            tvalue = (char*)alloca(value_len+1);
            memcpy(tvalue, value, value_len);
            tvalue[value_len] = '\0';

            vcur = (FieldValue*)alloca(sizeof(FieldValue));
            memset(vcur, 0, sizeof(FieldValue));

            vcur->value = tvalue;

            if (vtail)
            {
               vtail->next = vcur;
               vtail = vcur;
            }
            else
               fcur->value = vtail = vcur;
         }
      } // if message_confirmed
   } // end of while(get_bc_line())

   // purge response if we fell out
   while(bc_get_next_line(&bc, &line, &line_len))
      ;

  execute_pop_callback:
   if (pmu)
      return (*pmu)(popc, froot, &bc);
   else
      return 1;

  purge_response_return_error:
   // read until end-of-transmission
   while(bc_get_next_line(&bc, &line, &line_len))
      ;

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

int mcb_send_unlined_data(MParcel *mp, const char *str)
{
   int bytes_sent;
   mp->total_sent += bytes_sent = stk_simple_send_unlined(mp->stalker, str, strlen(str));
   return bytes_sent;
}

int mcb_send_data_endline(MParcel *mp)
{
   int bytes_sent;
   mp->total_sent += bytes_sent = stk_simple_send_unlined(mp->stalker, "\r\n", 2);
   return bytes_sent;
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

int mcb_send_line(MParcel *mp, const char *line, int line_len)
{
   int bytes_sent = 0;
   mp->total_sent += bytes_sent = stk_simple_send_line(mp->stalker, line, line_len);
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
 * @brief Writes a GUID value to the guid_buffer.
 *
 * The required buffer length for a proper GUID, a 128-bit long
 * hex value broken with hyphens into 5 sections, is 37 characters.
 *
 * -  32 characters for the 128-bits of random data
 * - + 4 characters for the hyphens separating the sections,
 * - + 1 for \0 terminator.
 *
 * The function returns 0 if it can't read 16 bytes from /dev/urandom
 * or if *buffer_len* == 0 (no room for final \0).
 * 
 * The result will be truncated if the *buffer_len* parameter
 * indicates that the buffer is too small.
 *
 * The last character in the *guid_buffer* will be set to \0, even
 * if that means the last character will be left-off.
 */
int mcb_make_guid(char *guid_buffer, int buffer_len)
{
   char *tend = &guid_buffer[buffer_len];
   char *tptr = guid_buffer;

   if (buffer_len < 1)
      return 0;

   uint8_t buffer[16];
   uint8_t *bend = &buffer[16];
   uint8_t *bptr = buffer;

   uint8_t *version_byte = &buffer[6];
   uint8_t *variant_byte = &buffer[8];

   size_t bytes_read;

   FILE *dr = fopen("/dev/urandom", "r");
   if (dr)
   {
      bytes_read = fread(buffer, 1, 16, dr);
      if (bytes_read == 16)
      {
         while (bptr < bend && tptr+1 < tend)
         {
            // Modify bytes for version and variant
            if (bptr == version_byte)
               *bptr = 64 | ( *bptr & 15 );  // Set first 4 bits to 1000
            else if (bptr == variant_byte)
               *bptr = 128 | (*bptr & 63 );  // Set first 2 bits to 10

            hexify_digit(tptr, *(uint8_t*)bptr);

            ++bptr;
            tptr += 2;

            // Add hyphens
            switch(bptr - buffer)
            {
               case 4:
               case 6:
               case 8:
               case 10:
                  if (tptr < tend)
                     *tptr++ = '-';
                  break;
               default:
                  break;
            }
         }
      }
      else
         return 0;

      fclose(dr);
   }
   else
      return 0;

   guid_buffer[buffer_len-1] = '\0';
   return 1;
}


/**
 * @brief Simple callback function for init_buff_control().
 */
size_t mcb_talker_reader(void *stalker, char *buffer, int buffer_len)
{
   return stk_recv_line((STalker*)stalker, buffer, buffer_len);
}

int mcb_is_opening_smtp(const MParcel *parcel)
{
  return !parcel->pop_reader;
}

/**
 * @brief Initialize connection with specified URL on specified port.
 *        Initializes TLS if requested.
 *
 * This function opens a socket, the opens SSL if requested.  In either
 * case, a STalker object is initialized and returned to the caller
 * through the MParcel pointer.
 */
void mcb_prepare_talker(MParcel *parcel, ServerReady talker_user)
{
   const char *host = parcel->host_url;
   int         port = parcel->host_port;

   char        buffer[1024];
   int         bytes_read;
   int         socket_response;
   int         smtp_mode_socket = 0;

   int osocket = get_connected_socket(host, port);
   if (osocket > 0)
   {
      STalker talker;
      init_sock_talker(&talker, osocket);
      parcel->stalker = &talker;

      if (mcb_is_opening_smtp(parcel))
      {
         bytes_read = mcb_recv_data(parcel, buffer, sizeof(buffer));
         socket_response = atoi(buffer);
         if (socket_response >= 200 && socket_response < 300)
         {
            smtp_mode_socket = 1;
            smtp_initialize_session(parcel);
         }
      }

      if (parcel->starttls)
      {
         // For SMTP using TLS, we must explicitly start tls
         if (smtp_mode_socket && parcel->caps.cap_starttls)
         {
            mcb_advise_message(parcel, "Starting TLS", NULL);

            mcb_send_data(parcel, "STARTTLS", NULL);
            bytes_read = mcb_recv_data(parcel, buffer, sizeof(buffer));
            if (bytes_read > 3)
            {
               socket_response = atoi(buffer);
               if (socket_response >= 200 && socket_response < 300)
               {
                  // For GMail, at least, the capabilities have changed,
                  // so we'll reaquire them now.
                  /* smtp_initialize_session(parcel); */

                  open_ssl(parcel, osocket, talker_user);
               }
               else
               {
                  buffer[bytes_read] = '\0';
                  mcb_log_message(parcel, "STARTTLS failed (", buffer, ")", NULL);
               }
            }
            else
               mcb_log_message(parcel, "Corrupt response to STARTTLS.", NULL);
         }
         else // Non-SMTP (ie POP) using TLS:
            open_ssl(parcel, osocket, talker_user);
      }
      else // Not using TLS
         (*talker_user)(parcel);

      close(osocket);
   }
}

void mcb_parse_header_line(const char *buffer,
                           const char *end,
                           const char **name,
                           int *name_len,
                           const char **value,
                           int *value_len)
{
   *name = *value = NULL;
   *name_len = *value_len = 0;

   // Abort if it's a zero-length line:
   if (end <= buffer)
      return;

   // Progress flags
   int done_with_name = 0;

   // If the first character is a space, we're on a follow-on
   // value.  There will be no name
   if (isspace(*buffer))
      done_with_name = 1;

   const char *spaces;
   const char *ptr = buffer;
   while (ptr < end)
   {
      if (!done_with_name)
      {
         if (*ptr == ':')
         {
            *name = buffer;
            spaces = ptr;

            while (isspace(*--spaces))
               ;

            // spaces now points to the last character of the string,
            // instead of the character just after.  We need to add
            // one to the difference in order to make the value mean
            // the same thing as elsewhere.
            ++spaces;

            *name_len = spaces - buffer;

            done_with_name = 1;
         }
      }
      // skip post-colon spaces to find beginning of value
      else if (!isspace(*ptr))
      {
         *value = ptr;
         break;
      }

      ++ptr;
   }

   if (done_with_name && *value)
   {
      // Walk back any trailing spaces
      spaces = end;
      while (isspace(*--spaces))
         ;
      // See comment about spaces above.
      spaces++;

      *value_len = spaces - *value;
   }
   else
   {
      *name = buffer;
      *name_len = spaces - buffer;
   }
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
               if (send_pop_message_header(&popc))
                  ++popc.message_index;
               else
                  break;
            }

            if (popc.message_index < popc.message_count)
               mcb_log_message(parcel, "Early termination of email retrieval.", NULL);
         }
      }
   }
}

void mcb_send_email_new(MParcel *parcel,
                        RecipLink *recipients,
                        const HeaderField *headers,
                        BuffControl *bc,
                        EmailLineJudge line_judger,
                        EmailSectionPrinter section_printer)
{
   const char *line;
   int        line_len;

   if (smtp_send_envelope(parcel, recipients))
   {
      if (parcel->OnlySendEnvelope)
      {
         ;
      }
      else if (smtp_send_headers(parcel, recipients, headers))
      {
         if (bc_get_current_line(bc, &line, &line_len))
         {
            if (LJ_End_Section == (*line_judger)(line, line_len))
               (*section_printer)(parcel, line, line_len);

            // Loop to read and send lines until end of message:
            while (bc_get_next_line(bc, &line, &line_len))
            {
               switch((*line_judger)(line, line_len))
               {
                  case LJ_Continue:
                     mcb_send_line(parcel, line, line_len);
                     break;
                  case LJ_End_Section:
                     (*section_printer)(parcel, line, line_len);
                     break;
                  case LJ_End_Message:
                     goto end_message;
               }
            }
         }

        end_message:

         if (mcb_smtp_get_multipart_flag(parcel))
            mcb_smtp_send_mime_end(parcel);

         mcb_send_data(parcel, ".", NULL);

         goto bypass_failure_flush;
      }
      else
         mcb_log_message(parcel, "Headers not accepted.", NULL);
   }
   else
      mcb_log_message(parcel, "Envelope not accepted.", NULL);

   // skip or failure_flush:
   // flush message after envelope or header failure:
   while (bc_get_next_line(bc, &line, &line_len))
      if (LJ_End_Message == (*line_judger)(line, line_len))
         break;

  bypass_failure_flush:
   // Send recipients results even if envelope fails
   // in case a RCPT_TO failure caused the envelope failure.
   if (parcel->report_recipients)
      (*parcel->report_recipients)(parcel, recipients);
}


