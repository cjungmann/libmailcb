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

typedef void (*Set_Cap_Func)(MParcel *mp, const char *line);

void parse_auth_options(MParcel *parcel, const char *line, int line_len)
{
}

typedef struct _cap_string
{
   const char   *str;
   int          len;
   Set_Cap_Func set_cap;

} CapString;

CapString capstrings[] = {
   {"AUTH",                 4, set_auth},
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
         (*ptr->set_cap)(parcel, line);

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
            fprintf(stderr, "Error processing replys from \"%s\"\n", buffer);
         case 0:
            ptr = end;  // set ptr to break loop
            break;
         default:
            if (status == 250)
               parse_capability_response(parcel, line, line_len);

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
   int bytes_read, total_read = 0;
   int bytes_sent, total_sent = 0;
   char buffer[1024];

   const char *host = parcel->host_url;

   STalker stalker;
   STalker *pstk = &stalker;
   init_sock_talker(pstk, socket_handle);

   // Read response from socket connection?  I don't know why,
   // but we need to read the response before getting anything.
   total_read += bytes_read = stk_recv_line(pstk, buffer, sizeof(buffer));

   advise_message(parcel, "About to greet server.", NULL);

   total_sent += bytes_sent = stk_send_line(pstk, "EHLO ", host, NULL);
   total_read += bytes_read = stk_recv_line(pstk, buffer, sizeof(buffer));
   parse_greeting_response(parcel, buffer, sizeof(buffer));

   // If the profile asks for STARTTLS AND the server offers STARTTLS, do it.
   if (parcel->starttls != 0 && get_starttls(parcel))
   {
      total_sent += bytes_sent = stk_send_line(pstk, "STARTTLS", NULL);
      total_read += bytes_read = stk_recv_line(pstk, buffer, sizeof(buffer));

      printf("STARTTLS response is:\n[44;1m%.*s[m\n", bytes_read, buffer);
      // start tls mode, then re-greet and get new capabilities.
      // Only if STARTTLS and AUTH are not both included (a la gmail).
   }
   else
   {
      printf("Expected STARTTLS in :\n[44;1m%.*s[m\n", bytes_read, buffer);
      advise_message(parcel, "Proceeding without STARTTLS.", NULL);
   }

   return 0;
}

