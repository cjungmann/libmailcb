#include <stdio.h>
#include <alloca.h>
#include <unistd.h>    // for close() function
#include <string.h>    // for memcpy, memset.

#include "mailcb.h"
#include <readini.h>

#define SECTION_DELIM '\v'
#define MESSAGE_DELIM '\f'

int end_of_email_message(const char *line, int line_len)
{
   return (line_len == 1 && *line == MESSAGE_DELIM);
}

typedef struct _mailer_data
{
   int  read_file;
   FILE *file_to_read;
} MailerData;

typedef struct _line_link
{
   const char *line_str;
   struct _line_link *next;
} LineLink;

void send_the_email(MParcel *parcel, LineLink *recipients, LineLink *headers, LineLink *body)
{
   int recip_count = 0;
   int field_count = 0;
   int body_count = 0;
   LineLink *ptr;
   const char **aptr;

   // Convert recipients chain to NULL-terminated char* array
   ptr = recipients;
   while (ptr)
   {
      ++recip_count;
      ptr = ptr->next;
   }

   const char **arr_recipients = (const char**)alloca(sizeof(char*) * (recip_count + 1));
   aptr = arr_recipients;
   ptr = recipients;
   while (ptr)
   {
      *aptr = ptr->line_str;
      ++aptr;

      ptr = ptr->next;
   }
   *aptr = NULL;

   // Convert headers chain to NULL-terminated char* array
   ptr = headers;
   while (ptr)
   {
      ++field_count;
      ptr = ptr->next;
   }

   const char **arr_fields = (const char**)alloca(sizeof(char*) * (field_count + 1));
   aptr = arr_fields;
   ptr = headers;
   while (ptr)
   {
      *aptr = ptr->line_str;
      ++aptr;

      ptr = ptr->next;
   }
   *aptr = NULL;

   // Convert message body chain to NULL-terminated char* array
   ptr = body;
   while (ptr)
   {
      ++body_count;
      ptr = ptr->next;
   }

   const char **arr_blines = (const char**)alloca(sizeof(char*) * (body_count + 1));
   aptr = arr_blines;
   ptr = body;
   while (ptr)
   {
      *aptr = ptr->line_str;
      ++aptr;

      ptr = ptr->next;
   }
   *aptr = NULL;
   
   char snum_rcount[10];
   char snum_fcount[10];
   char snum_bcount[10];

   mcb_itoa_buff(recip_count, 10, snum_rcount, sizeof(snum_rcount));
   mcb_itoa_buff(field_count, 10, snum_fcount, sizeof(snum_fcount));
   mcb_itoa_buff(body_count, 10, snum_bcount, sizeof(snum_bcount));
   mcb_advise_message(parcel,
                      "Sending email with ",
                      snum_rcount,
                      " recipients and ",
                      snum_fcount,
                      " header fields and ",
                      snum_bcount,
                      " body lines.",
                      NULL);
}

/**
 * @brief Return the number of bytes to the last character of the line.
 *
 * This function finds the \r or \n that terminates a line
 * and returns the number of bytes to the character just before
 * the line-terminator character(s).
 *
 * If no end-line can be detected, the function returns -1
 *
* The calling function is responsible for skipping past the
 * line-terminator character(s).
 */
int detect_line(const char *source, const char *end)
{
   const char *ptr = source;
   while (ptr < end && *ptr != '\r' && *ptr != '\n')
      ++ptr;

   if (ptr==end)
      return -1;
   else
      return ptr - source;
}


/**
 * @brief Send parsed email
 *
 * Separated out of email_from_file_read_headers() to provide a shortcut
 * that bypasses email_from_file_read_headers().
 */
void email_from_file_final_send(MParcel *parcel,
                                BuffControl *bc,
                                RecipLink *recips,
                                const HeaderField *headers)
{
   mcb_send_email_new(parcel, recips, headers, bc, end_of_email_message);
}

/**
 * @brief Continue email file parsing after reading recipients.
 */
void email_from_file_read_headers(MParcel *parcel, BuffControl *bc, RecipLink *recips)
{
   const char *line;
   int line_len;

   const char *name, *value;
   int name_len, value_len;

   char *tline;

   HeaderField *h_root = NULL, *h_tail = NULL, *h_cur;
   FieldValue *v_tail = NULL, *v_cur;

   while (get_bc_line(bc, &line, &line_len))
   {
      if (line_len == 1 && (*line == MESSAGE_DELIM || *line == SECTION_DELIM))
         break;

      // Split line into name/value parts
      mcb_parse_header_line(line, &line[line_len], &name, &name_len, &value, &value_len);

      if (name_len)
      {
         // Make empty link
         h_cur = (HeaderField*)alloca(sizeof(HeaderField));
         memset(h_cur, 0, sizeof(HeaderField));

         // Attach link to chain
         if (h_tail)
         {
            h_tail->next = h_cur;
            h_tail = h_cur;
         }
         else
            h_root = h_tail = h_cur;

         tline = (char*)alloca(name_len+1);
         memcpy(tline, line, name_len);
         tline[name_len] = '\0';
         h_cur->name = tline;

         v_cur = NULL;
      }

      if (value_len && h_cur)
      {
         if (v_tail)
         {
            v_cur = (FieldValue*)alloca(sizeof(FieldValue));
            v_tail->next = v_cur;
            v_tail = v_cur;
         }
         else
            v_cur = &h_cur->value;

         tline = (char*)alloca(value_len+1);
         memcpy(tline, line, value_len);
         tline[name_len] = '\0';
         v_cur->value = tline;
      }
   }

   email_from_file_final_send(parcel, bc, recips, h_root);
}

/**
 * @brief Commence processing email by collecting recipients.
 */
void email_from_file_read_recipients(MParcel *parcel, BuffControl *bc)
{
   const char *line;
   int line_len;

   char *tline;

   RecipLink *rl_root = NULL, *rl_tail = NULL, *rl_cur;

   while (get_bc_line(bc, &line, &line_len))
   {
      if (line_len == 1 && (*line == SECTION_DELIM  || *line == MESSAGE_DELIM))
         break;

      // Make empty link
      rl_cur = (RecipLink*)alloca(sizeof(RecipLink));
      memset(rl_cur, 0, sizeof(RecipLink));

      // Attach link to chain
      if (rl_tail)
      {
         rl_tail->next = rl_cur;
         rl_tail = rl_cur;
      }
      else
         rl_root = rl_tail = rl_cur;

      // Set link member values
      switch(*line)
      {
         case '+':
            rl_cur->rtype = RT_CC;
            break;
         case '-':
            rl_cur->rtype = RT_BCC;
            break;
         case '#':
            rl_cur->rtype = RT_SKIP;
            break;
      }

      if (rl_cur->rtype)
      {
         --line_len;
         tline = (char*)alloca(line_len+1);
         memcpy(tline, line+1, line_len);
      }
      else
      {
         tline = (char*)alloca(line_len+1);
         memcpy(tline, line, line_len);
      }

      tline[line_len] = '\0';
      rl_cur->address = tline;
   }

   if (line_len == 1)
   {
      if (*line == SECTION_DELIM)
         email_from_file_read_headers(parcel, bc, rl_root);
      else if (*line == MESSAGE_DELIM)
         email_from_file_final_send(parcel, bc, rl_root, NULL);
   }
   // If premature exit, warn and return without sending:
   else if (line_len == 0)
      mcb_log_message(parcel, "Incomplete email not sent.", NULL);
   else
      mcb_log_message(parcel, "Unexpected exit from recipient-reading loop.", NULL);
}

void report_recipients(MParcel *parcel, RecipLink *rchain)
{
   if (parcel->verbose)
   {
      int cur_len, max_len = 0;
      RecipLink *ptr = rchain;
      while (ptr)
      {
         cur_len = strlen(ptr->address);
         if (cur_len > max_len)
            max_len = cur_len;

         ptr = ptr->next;
      }

      ptr = rchain;
      while (ptr)
      {
         printf("%*s: %d.\n", max_len, ptr->address, ptr->rcpt_status);
         ptr = ptr->next;
      }
   }
}

void emails_from_file(MParcel *parcel)
{
   FILE *efile = ((MailerData*)parcel->data)->file_to_read;
   char buffer[1024];

   BuffControl bc;
   init_buff_control(&bc, buffer, sizeof(buffer), bc_file_reader, (void*)efile);

   email_from_file_read_recipients(parcel, &bc);
}


void emails_from_file_old(MParcel *parcel)
{
   FILE *efile = ((MailerData*)parcel->data)->file_to_read;

   char buffer[1024];
   size_t bytes_read;
   int offset;

   // 0 for recipients, 1, for headers, 2 for message, 3 email complete
   int content_state = 0;

   // Use pointer to test for end, rather than index
   const char *end;

   LineLink *recipients = NULL;
   LineLink *headers = NULL;
   LineLink *body = NULL;

   LineLink *tail = NULL;
   LineLink *work_ll;

   char *line, *work_str;
   int line_len;

   // If the last character of a buffer is \r, we'll ignore
   // an \n in the first character of the buffer
   char buffer_ending_char = '\0';

   // The first character of the buffer should always be
   // the first character of a line.  If a line is truncated
   // at the end of the buffer, the beginning of the current
   // line should be memmove-d to the beginning of the buffer,
   // and the offset set to begin reading at the end of previous
   // transmission.

   offset = 0;
   while ((bytes_read = fread(&buffer[offset], 1, sizeof(buffer) - offset, efile)))
   {
      // Mark end of read data
      end = &buffer[bytes_read + offset];

      // Skip inital \n if it was separated from a preceding \r
      if (buffer_ending_char == '\r' && *buffer == '\n')
         line = &buffer[1];
      else
         line = buffer;

      // Extract lines from the buffer
      while ((line_len=detect_line(line, end)) >= 0)
      {
         // Make new LineLink with the string:
         work_ll = (LineLink*)alloca(sizeof(LineLink));
         memset(work_ll, 0, sizeof(LineLink));

         // Add string only if available, otherwise leave
         // work_ll == NULL to indicate an empty line;
         if (line_len > 0)
         {
            work_str = (char*)alloca(line_len+1);
            memcpy(work_str, line, line_len);
            work_str[line_len] = '\0';

            work_ll->line_str = work_str;
         }

         // Add the link to the current chain
         if (tail)
         {
            tail->next = work_ll;
            tail = work_ll;
         }
         // or begin a new chain
         else if (content_state == 0)
            recipients = tail = work_ll;
         else if (content_state == 1)
            headers = tail = work_ll;
         else
            body = tail = work_ll;

         // Prepare for next iteration of the while loop:

         // Move to start of next line:
         line += line_len;
         buffer_ending_char = *line;
         while (line < end && (*line == '\r' || *line == '\n'))
            ++line;

         // If end of recipients or headers section (marked by SECTION_DELIM),
         // clear *tail to trigger next operation
         if (line < end)
         {
            // vertical tab between sections, form-feed between emails
            if (*line == SECTION_DELIM || *line == MESSAGE_DELIM)
            {
               // Advance the content state (recipients, headers, body)
               ++content_state;

               // Ignore the SECTION_DELIM or MESSAGE_DELIM, once detected
               ++line;
               tail = NULL;
            }

            // If email contents complete, send and reset for next email
            if (content_state > 2)
            {
               send_the_email(parcel, recipients, headers, body);
               recipients = headers = body = NULL;
               content_state = 0;
            }
         }
      } // end line-reading while loop


      // If incomplete line, move it to the beginning of the buffer
      // before reading more from the FILE
      if (line > buffer)
      {
         offset = end - line;
         memmove(buffer, line, offset);
         continue;
      }
   }

   // fread has exhausted the input file, we're done.

   // Send email-in-process if complete the terminating
   // MESSAGE_DELIM  was omitted and the email includes a body:
   if (content_state > 2)
      send_the_email(parcel, recipients, headers, body);
}




























int update_if_needed(const char *name, const ri_Line *line, const char **target, const MParcel *parcel)
{
   if (*target == NULL)
      if (0 == strcmp(line->tag, name))
      {
         *target = line->value;
         return 1;
      }

   return 0;
}































void begin_smtp_conversation(MParcel *parcel)
{
   if (mcb_authorize_smtp_session(parcel))
   {
      parcel->report_recipients = report_recipients;

      if (((MailerData*)parcel->data)->read_file)
         emails_from_file(parcel);
      else
         mcb_log_message(parcel, "No file from which to read emails.", NULL);
   }
   else
      mcb_log_message(parcel, "SMTP session authorization failed.", NULL);
}

/**
 * @brief Callback function for processing pop headers.  For parcel->pop_message_receiver.
 *
 * We get here if popc->parcel->pop_reader!=0 && popc->parcel->pop_message_receiver!=NULL
 */
int pop_message_receiver(PopClosure *popc, const HeaderField *fields, BuffControl *bc)
{
   const HeaderField *fptr;
   const FieldValue *vptr;
   int str_len, max_name_len = 0;

   // Write progress to stderr to keep user informed
   fprintf(stderr,
           "[33;1mReading message %4d of %4d.[m\r",
           popc->message_index+1,
           popc->message_count);

   // Header for each email:
   printf("### Message %4d of %4d.\n",
          popc->message_index+1,
          popc->message_count);

   fptr = fields;
   while (fptr)
   {
      str_len = strlen(fptr->name);
      if (str_len > max_name_len)
         max_name_len = str_len;

      fptr = fptr->next;
   }

   /* printf("\n[34;1m"); */
   fptr = fields;
   while (fptr)
   {
      printf("%*s: ", max_name_len, fptr->name);

      vptr = &fptr->value;

      while (vptr)
      {
         if (vptr->value)
         {
            // Spaces to line if on a field value continuation
            if (vptr != &fptr->value)
               printf("%*s  ", max_name_len, "  ");

            // puts adds a newline, don't add another!
            puts(vptr->value);
         }

         vptr = vptr->next;
      }

      fptr = fptr->next;
   }
   /* printf("[m\n"); */

   return 1;
}

/**
 * @brief Begins task after processing CLI arguments and .conf file settings
 */
void talker_user(MParcel *parcel)
{
   mcb_advise_message(parcel, "Entered the talker_user function.", NULL);

   if (mcb_is_opening_smtp(parcel))
      begin_smtp_conversation(parcel);
   else
      mcb_greet_pop_server(parcel);
}

void begin_after_read_config_attempt(const ri_Section *root, void* mparcel)
{
   MParcel *parcel = (MParcel*)mparcel;
   const ri_Section *section;
   const ri_Line *line;

   // Update parcel with config file data, if available:
   if (root)
   {
      const char *acct = parcel->account;
      if (!acct)
         acct = ri_find_section_value(root, "defaults", "default-account");

      if (acct)
      {
         mcb_advise_message(parcel, "Using configuration account \"", acct, "\"", NULL);

         section = ri_get_section(root, acct);
         if (section)
         {
            line = section->lines;
            while (line)
            {
               if (update_if_needed("host", line, &parcel->host_url, parcel))
                  goto next_line;

               if (update_if_needed("user", line, &parcel->login, parcel))
                  goto next_line;

               if (update_if_needed("from", line, &parcel->from, parcel))
                  goto next_line;

               if (update_if_needed("password", line, &parcel->password, parcel))
                  goto next_line;

               if (0 == parcel->host_port && 0 == strcmp(line->tag, "port"))
               {
                  parcel->host_port = atoi(line->value);
                  goto next_line;
               }

               if (0 == parcel->starttls
                   && 0 == strcmp(line->tag, "use_tls")
                   && 0 == strcmp(line->value, "on"))
               {
                  parcel->starttls = 1;
                  goto next_line;
               }

               if (0 == parcel->pop_reader
                   && 0 == strcmp(line->tag, "type")
                   && 0 == strcmp(line->value, "pop"))
               {
                  parcel->pop_reader = 1;
                  parcel->callback_func = mcb_greet_pop_server;
                  parcel->pop_message_receiver = pop_message_receiver;
                  goto next_line;
               }

              next_line:
               line = line->next;
            }
         }
         else
            mcb_log_message(parcel, "Failed to find configuration account \"", acct, "\"", NULL);
      }
   }

   mcb_prepare_talker(parcel, talker_user);
}

void show_usage(void)
{
   const char* text = 
      "-a account to use\n"
      "-c config file path\n"
      "-f from email address\n"
      "-h host url\n"
      "-i email input file, '-' for stdin\n"
      "-l login name\n"
      "-p port number\n"
      "-r POP3 reader\n"
      "-q quiet, suppress error messages\n"
      "-t use TLS encryption\n"
      "-v generate verbose output\n"
      "-w password\n";

   printf("%s\n", text);
}

int main(int argc, const char** argv)
{
   MParcel mparcel;
   memset(&mparcel, 0, sizeof(mparcel));
   mparcel.logfile = stderr;
   mparcel.callback_func = begin_smtp_conversation;

   MailerData md = { 0 };
   mparcel.data = (void*)&md;

   // process command line arguments:
   const char **cur_arg = argv;
   const char **end_arg = cur_arg + argc;
   const char *str;

   const char *config_file_path = "./mailer.conf";
   const char *input_file_path = NULL;

   // Advise access to help if command called with no arguments:
   if (argc == 1)
   {
      printf("-? for help.\n");
      goto abort_program;
   }

   while (cur_arg < end_arg)
   {
      str = *cur_arg;

      if (*str == '-')
      {
         // If the argument is a single '-':
         if (*(str+1) == '\0')
         {
            input_file_path = "-";
            md.read_file = 1;
            goto continue_next_arg;
         }

         while (*++str)
         {
            switch(*str)
            {
               case 'a':  // config account to use
                  if (cur_arg + 1 < end_arg)
                  {
                     mparcel.account = *++cur_arg;
                     goto continue_next_arg;
                  }
                  break;
               case 'c':  // config file
                  if (cur_arg + 1 < end_arg)
                  {
                     config_file_path = *++cur_arg;
                     goto continue_next_arg;
                  }
                  break;
               case 'f':  // from
                  if (cur_arg + 1 < end_arg)
                  {
                     mparcel.from = *++cur_arg;
                     goto continue_next_arg;
                  }
                  break;
               case 'h':  // host
                  if (cur_arg + 1 < end_arg)
                  {
                     mparcel.host_url = *++cur_arg;
                     goto continue_next_arg;
                  }
                  break;
               case 'i':  // read batch emails from a file
                  if (cur_arg + 1 < end_arg)
                  {
                     input_file_path = *++cur_arg;
                     md.read_file = 1;
                     goto continue_next_arg;
                  }
                  break;
               case 'l':  // login
                  if (cur_arg + 1 < end_arg)
                  {
                     mparcel.login = *++cur_arg;
                     goto continue_next_arg;
                  }
                  break;
               case 'p':  // port
                  if (cur_arg + 1 < end_arg)
                  {
                     mparcel.host_port = atoi(*++cur_arg);
                     goto continue_next_arg;
                  }
                  break;
               case 'r':  // POP3 reader
                  mparcel.pop_reader = 1;
                  mparcel.callback_func = mcb_greet_pop_server;
                  mparcel.pop_message_receiver = pop_message_receiver;
                  break;
               case 'q':  // quiet, suppress error messages
                  mparcel.quiet = 1;
                  break;
               case 't':   // tls
                  mparcel.starttls = 1;
                  break;
               case 'v':  // verbose messages
                  mparcel.verbose = 1;
                  break;
               case 'w':  // passWord
                  if (cur_arg + 1 < end_arg)
                  {
                     mparcel.password = *++cur_arg;
                     goto continue_next_arg;
                  }
               default:
                  printf("'%c' is not a valid argument.\n", *str);
               case '?':  // show help
                  show_usage();
                  goto abort_program;
                  break;
            }
         }
      }

     continue_next_arg:
      ++cur_arg;
   }

   if (input_file_path)
   {
      if (0 == strcmp(input_file_path, "-"))
      {
         md.file_to_read = stdin;
         md.read_file = 1;
      }
      else
      {
         md.file_to_read = fopen(input_file_path, "r");
         if (md.file_to_read)
            md.read_file = 1;
         else
         {
            mcb_log_message(&mparcel,
                            "Failed to open \"",
                            input_file_path,
                            "\", ",
                            strerror(errno),
                            NULL);

            return 1;
         }
      }
   } // end of while (cur_arg < end_arg)


   int access_result;
   if (config_file_path
       && 0 == (access_result = access(config_file_path, F_OK|R_OK)))
   {
      mcb_advise_message(&mparcel, "About to open config file \"", config_file_path, "\"", NULL);
      ri_read_file(config_file_path,
                   begin_after_read_config_attempt,
                   (void*)&mparcel);
   }
   else
   {
      mcb_advise_message(&mparcel, "Failed to find configuration file.", NULL);
      begin_after_read_config_attempt(NULL, (void*)&mparcel);
   }

   if (md.file_to_read && md.file_to_read != stdin)
      fclose(md.file_to_read);

  abort_program:
   return 0;
}







