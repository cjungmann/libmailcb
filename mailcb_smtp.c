#include <code64.h>
#include <string.h>

#include "socktalk.h"
#include "mailcb.h"
#include "commparcel.h"

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
 * @brief Send EHLO and process the response to the MParcel Caps member.
 */
void smtp_initialize_session(MParcel *parcel)
{
   char buffer[1024];
   int bytes_read;

   mcb_send_data(parcel, "EHLO ", parcel->host_url, NULL);
   bytes_read = mcb_recv_data(parcel, buffer, sizeof(buffer));
   smtp_parse_greeting_response(parcel, buffer, bytes_read);
}

/**
 * @brief Used by smtp_parse_greeting_response() to interpret the EHLO response.
 */
void smtp_parse_capability_response(MParcel *parcel, const char *line, int line_len)
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
void smtp_parse_greeting_response(MParcel *parcel, const char *buffer, int buffer_len)
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
                  smtp_parse_capability_response(parcel, line, line_len);
            }

            ptr += advance_chars;
            break;
      }
   }
}

/**
 * @brief Improved function that individually tracks address acceptance.
 */
int smtp_send_envelope(MParcel *parcel, RecipLink *recipients)
{
   if (!recipients)
      return 0;

   char buffer[1024];
   RecipLink *ptr = recipients;
   int bytes_read;
   int recipients_accepted = 0;
   int reply_status;
   mcb_send_data(parcel, "MAIL FROM: <", parcel->from, ">", NULL);
   bytes_read = mcb_recv_data(parcel, buffer, sizeof(buffer));

   reply_status = atoi(buffer);
   if (reply_status >= 200 && reply_status < 300)
   {
      while (ptr)
      {
         if (ptr->rtype != RT_SKIP)
         {
            mcb_send_data(parcel, "RCPT TO: <", ptr->address, ">", NULL);

            bytes_read = mcb_recv_data(parcel, buffer, sizeof(buffer));
            buffer[bytes_read] = '\0';

            reply_status = atoi(buffer);
            ptr->rcpt_status = reply_status;

            if (reply_status >= 200 && reply_status < 300)
               ++recipients_accepted;
            else
               mcb_log_message(parcel,
                               "Recipient, ",
                               *ptr,
                               ", was turned down by the server, \"",
                               buffer,
                               "\"",
                               NULL);
         }

         ptr = ptr->next;
      }

      if (recipients_accepted)
      {
         mcb_send_data(parcel, "DATA", NULL);
         bytes_read = mcb_recv_data(parcel, buffer, sizeof(buffer));
         reply_status = atoi(buffer);
         if (reply_status >= 200 && reply_status < 400)
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
 * @brief Internal function for mcb_send_email_new() to send email headers.
 */
int smtp_send_headers(MParcel *parcel,
                      RecipLink *recipients,
                      const HeaderField *headers)
{
   if (!recipients)
      return 0;

   RecipLink *rptr = recipients;

   int to_count = 0;
   int cc_count = 0;
   int bcc_count = 0;
   int needs_comma;

   rptr = recipients;
   while (rptr)
   {
      if (rptr->rcpt_status < 300)
      {
         switch(rptr->rtype)
         {
            case RT_TO:
               ++to_count;
               break;
            case RT_CC:
               ++cc_count;
               break;
            case RT_BCC:
               ++bcc_count;
               break;
            case RT_SKIP:
               break;
         }
      }
      rptr = rptr->next;
   }

   mcb_send_data(parcel, "From: ", parcel->from, NULL);

   // Send all the accepted To: recipients
   if (to_count)
   {
      mcb_send_unlined_data(parcel, "To: ");
      rptr = recipients;
      needs_comma = 0;
      while (rptr)
      {
         if (rcpt_status_ok(rptr) && rptr->rtype == RT_TO)
         {
            if (needs_comma)
               mcb_send_unlined_data(parcel, ", ");
            else
               needs_comma = 1;

            mcb_send_unlined_data(parcel, rptr->address);
         }

         rptr = rptr->next;
      }

      mcb_send_data_endline(parcel);
   }

   // Send all the accepted CC: recipients
   if (cc_count)
   {
      mcb_send_unlined_data(parcel, "Cc: ");
      rptr = recipients;
      needs_comma = 0;
      while (rptr)
      {
         if (rcpt_status_ok(rptr) && rptr->rtype == RT_CC)
         {
            if (needs_comma)
               mcb_send_unlined_data(parcel, ", ");
            else
               needs_comma = 1;

            mcb_send_unlined_data(parcel, rptr->address);
         }

         rptr = rptr->next;
      }

      mcb_send_data_endline(parcel);
   }

   // Send all the headers
   const HeaderField *hptr = headers;
   const FieldValue *vptr;
   while (hptr)
   {
      mcb_send_data(parcel, hptr->name, ": ", hptr->value->value, NULL);

      vptr = hptr->value->next;
      while (vptr)
      {
         mcb_send_data(parcel, "\t", vptr->value, NULL);
         vptr = vptr->next;
      }

      hptr = hptr->next;
   }

   if (mcb_smtp_get_multipart_flag(parcel))
      mcb_smtp_send_mime_announcement(parcel);
   
   // Send blank line to terminate headers
   mcb_send_data(parcel, "", NULL);

   return 1;
}

/**
 * @brief Initialize SMTP server conversation, submitting credentials if appropriate.
 *
 * @return 1 if success. Calling function must terminate the conversation with "QUIT" message to server.
 *         0 if failed.  Failure will terminate the conversation immediately,
 */
int mcb_smtp_greet_server(MParcel *parcel)
{
   char buffer[1024];
   int bytes_read;

   mcb_send_data(parcel, "EHLO ", parcel->host_url, NULL);
   bytes_read = mcb_recv_data(parcel, buffer, sizeof(buffer));
   smtp_parse_greeting_response(parcel, buffer, bytes_read);

   if (mcb_smtp_authorize_session(parcel))
      return 1;
   else
   {
      mcb_smtp_quit_server(parcel);
      return 0;
   }
}

/**
 * @brief Send account credentials to the SMTP server.
 */
int mcb_smtp_authorize_session(MParcel *parcel)
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

         mcb_send_data(parcel, buffer, NULL);
         bytes_received = mcb_recv_data(parcel, buffer, sizeof(buffer));
         buffer[bytes_received] = '\0';

         // reply status in the 300 range (334) indicates
         // good so far, but need more inputx
         reply_status = atoi(buffer);
         if (reply_status >= 300 && reply_status < 400)
         {
            c64_encode_to_buffer(password, strlen(password), (uint32_t*)&buffer, sizeof(buffer));

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


void mcb_smtp_clear_multipart_flag(MParcel *parcel)
{
   memset(parcel->multipart_boundary, 0, sizeof(parcel->multipart_boundary));
}

void mcb_smtp_set_multipart_flag(MParcel *parcel)
{
   if (!mcb_make_guid(parcel->multipart_boundary, sizeof(parcel->multipart_boundary)))
      mcb_smtp_clear_multipart_flag(parcel);
}

int mcb_smtp_get_multipart_flag(const MParcel *parcel)
{
   return *parcel->multipart_boundary != 0;
}

/**
 * @brief Send multipart/alternative email headers
 *
 * Generate a new GUID to use for the border strings, then
 * adds the Mime headers.
 *
 * Probably should be private to prevent multiple calls.
 */
void mcb_smtp_send_mime_announcement(MParcel *parcel)
{
   mcb_send_data(parcel, "MIME-Version: 1.0", NULL);
   mcb_send_data(parcel,
                 "Content-Type: multipart/alternative; boundary=",
                 parcel->multipart_boundary,
                 NULL);
   /* mcb_send_data(parcel, "Content-Type: multipart/alternative;", NULL); */
   /* mcb_send_data(parcel, "\tboundary=\"", parcel->multipart_boundary, "\"", NULL); */
   mcb_send_data_endline(parcel);
}

/**
 * @brief Used by the calling process to initialiate a new mime section.
 *
 * The section will use the border value generated earlier, when the multipart started.
 */
void mcb_smtp_send_mime_border(MParcel *parcel, const char *content_type, const char *charset)
{
   mcb_send_data(parcel, "--", parcel->multipart_boundary, NULL);
   mcb_send_data(parcel,
                 "Content-Type: ",
                 content_type,
                 "; charset=",
                 (charset?charset:"iso-8859-1"),
                 NULL);
   mcb_send_data(parcel, "Content-Transfer-Encoding: quoted-printable", NULL);
   mcb_send_data_endline(parcel);
}

void mcb_smtp_send_mime_end(MParcel *parcel)
{
   mcb_send_data(parcel, "--", parcel->multipart_boundary, "--", NULL);
}




/**
 * @brief Terminate SMTP server conversation (socket and/or SSL handle remain open).
 */
void mcb_smtp_quit_server(MParcel *parcel)
{
   char buffer[1024];
   mcb_send_data(parcel, "QUIT", NULL);
   mcb_recv_data(parcel, buffer, sizeof(buffer));

   mcb_advise_message(parcel, "SMTP server sendoff.", NULL);
}

