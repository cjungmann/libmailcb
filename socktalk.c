#include <stdarg.h>    // for va_arg, etc.
#include <string.h>    // for memset, etc;
#include "socktalk.h"


int walk_status_reply(const char *str, int *status, const char** line, int *line_len)
{
   int i_status = 0;

   if (! *str)
      return 0;

   // Initialize outputs, which will also be used as progress flags.
   *status = 0;
   *line = NULL;
   *line_len = 0;
      
   const char *ptr = str;
   while (*ptr && *ptr != '\r')
   {
      if (*status==0)
      {
         i_status *= 10;
         i_status += *ptr - '0';
         if (i_status > 99)
            *status = i_status;
      }
      else if (*line == NULL && *ptr!=' ' && *ptr!='-')
         *line = ptr;

      ++ptr;
   }

   if (! *ptr)
   {
      fprintf(stderr, "Unexpected end-of-string while parsing status reply.\n");
      return -1;
      /* return ptr - str; */
   }
   else if (*ptr == '\r')
   {
      *line_len = ptr - *line;
      if (*++ptr == '\n')
         // Move pointer to character just after \n:
         ++ptr;
      else
         fprintf(stderr, "Unexpected %c following a '\\r'.\n", *ptr);
   }

   return ptr - str;
}

void dump_status_reply(const char *buffer, int buffer_len)
{
   const char *ptr = buffer;
   const char *end = buffer  + buffer_len;

   int advance_chars;

   // walk_status_reply() output parameter variables
   int status;
   const char *line;
   int line_len;
   
   while (ptr < end && *ptr)
   {
      advance_chars = walk_status_reply(buffer, &status, &line, &line_len);
      switch(advance_chars)
      {
         case -1:
            fprintf(stderr, "Error processing replys from \"%s\"\n", buffer);
         case 0:
            ptr = end;  // Flag to break outer loop
            break;
         default:
            printf("%d : %.*s.\n", status, line_len, line);
            ptr += advance_chars;
            break;
      }
   }
}

int log_status_reply_errors(const char *buffer, int buffer_len)
{
   int errors = 0;
   const char *ptr = buffer;
   const char *end = buffer  + buffer_len;

   int advance_chars;

   // walk_status_reply() output parameter variables
   int status;
   const char *line;
   int line_len;
   
   while (ptr < end && *ptr)
   {
      advance_chars = walk_status_reply(buffer, &status, &line, &line_len);
      switch(advance_chars)
      {
         case -1:
            fprintf(stderr, "Error processing replys from \"%s\"\n", buffer);
         case 0:
            ptr = end;  // Flag to break outer loop
            break;
         default:
            if (status >= 400)
            {
               printf("Error (%d) : %.*s.\n", status, line_len, line);
               ++errors;
            }
            ptr += advance_chars;
            break;
      }
   }
   return errors;
}

int stk_sock_talker(const struct _stalker* talker, const void *data, int data_len)
{
   return send(talker->socket_handle, (void*)data, data_len, 0);
}

int stk_ssl_talker(const struct _stalker* talker, const void *data, int data_len)
{
   return SSL_write(talker->ssl_handle, data, data_len);
}

int stk_sock_reader(const struct _stalker* talker, void *buffer, int buff_len)
{
   return recv(talker->socket_handle, buffer, buff_len, 0);
}

int stk_ssl_reader(const struct _stalker* talker, void *buffer, int buff_len)
{
   return SSL_read(talker->ssl_handle, buffer, buff_len);
}


void init_ssl_talker(struct _stalker* talker, SSL* ssl)
{
   memset(talker, 0, sizeof(struct _stalker));
   talker->ssl_handle = (void*)ssl;
   talker->writer = stk_ssl_talker;
   talker->reader = stk_ssl_reader;
}

void init_sock_talker(struct _stalker* talker, int socket)
{
   memset(talker, 0, sizeof(struct _stalker));
   talker->socket_handle = socket;
   talker->writer = stk_sock_talker;
   talker->reader = stk_sock_reader;
}

/**
 * @brief Sends data by char* and byte count.  To be paired with use of BuffControl object.
 */
size_t stk_simple_send_line(const struct _stalker* talker, const char *data, int data_len)
{
   size_t bytes_sent = (*talker->writer)(talker, data, data_len);
   bytes_sent += (*talker->writer)(talker, "\r\n", 2);
   return bytes_sent;
}

/**
 * @brief Send raw string, without adding a newline. 
 *
 * This function is meant for building a line in multiple steps.
 * The main example is creating a comma-separated To: header field.
 */
size_t stk_simple_send_unlined(const struct _stalker* talker, const char *data, int data_len)
{
   return (*talker->writer)(talker, data, data_len);
}

size_t stk_vsend_line(const struct _stalker* talker, va_list args)
{
   size_t bytes_sent, total_bytes = 0;
   size_t bite_len;

   va_list args_copy;
   va_copy(args_copy, args);

   const char *bite = va_arg(args_copy, const char*);
   while (bite)
   {
      bite_len = strlen(bite);
      total_bytes += bytes_sent = (*talker->writer)(talker, bite, bite_len);
      if (bytes_sent != bite_len)
         fprintf(stderr, "Socket talker failed to write complete contents of string.\n");

      bite = va_arg(args_copy, const char*);
   }

   va_end(args_copy);

   total_bytes += bytes_sent = (*talker->writer)(talker, "\r\n", 2);

   return total_bytes;
}

/**
 * @brief Write string of const char* arguments to socket or ssl socket, finish with "\r\n";
 *
 * This is a variable-argument function, with the _talker argument first,
 * followed by const char* arguments, terminated with a NULL argument to
 * indicate the end of the list.
 *
 * No spaces will be added between argument strings, but a final "\r\n"
 * will be sent upon encountering the terminating NULL.
 */
size_t stk_send_line(const struct _stalker* talker, ...)
{
   size_t bytes_sent, total_bytes = 0;
   size_t bite_len;
   va_list ap;
   va_start(ap, talker);

   const char *bite = va_arg(ap, const char*);
   while (bite)
   {
      bite_len = strlen(bite);
      total_bytes += bytes_sent = (*talker->writer)(talker, bite, bite_len);
      if (bytes_sent != bite_len)
         fprintf(stderr, "Socket talker failed to write complete contents of string.\n");

      bite = va_arg(ap, const char*);
   }

   va_end(ap);

   total_bytes += bytes_sent = (*talker->writer)(talker, "\r\n", 2);

   return total_bytes;
}

/**
 * @brief Read from server using current communication protocol.  Add \0 to end, if room.
 */
size_t stk_recv_line(const struct _stalker* talker, void* buffer, int buff_len)
{
   size_t bytes_read = (*talker->reader)(talker, buffer, buff_len);
   if (bytes_read+1 < buff_len)
      ((char*)buffer)[bytes_read] = '\0';
   return bytes_read;
}

int stk_send_recv_line(const struct _stalker *talker, ...)
{
   char buffer[1000];

   va_list args;
   va_start(args, talker);
   stk_vsend_line(talker, args);
   va_end(args);

   stk_recv_line(talker, buffer, sizeof(buffer));
   return 0 == log_status_reply_errors(buffer, sizeof(buffer));
}

int seek_status_message(const struct _status_line* sl, const char *value)
{
   while (sl)
   {
      if ( 0 == strcasecmp(sl->message, value))
         return 1;
      sl = sl->next;
   }

   return 0;
}

void show_status_chain(const Status_Line *sl)
{
   while (sl)
   {
      printf("%d : \"[44;1m%s[m\"\n", sl->status, sl->message);
      sl = sl->next;
   }
}
