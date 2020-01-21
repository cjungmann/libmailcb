#include <stdio.h>
#include <alloca.h>
#include <unistd.h>  // for close() function
#include <string.h>  // for memcpy, memset.

#include "mailcb.h"
#include <readini.h>

#define SECTION_DELIM '\v'
#define MESSAGE_DELIM '\f'

/**
 * @brief Structure for passing data through MParcel::data.
 */
typedef struct _mailer_data
{
   int  read_file;
   FILE *file_to_read;
} MailerData;


/*************************************************************************/
/*                      SMTP mail sender processing                      */
/*************************************************************************/

void emails_from_file(MParcel *parcel);
void collect_email_recipients(MParcel *parcel, BuffControl *bc);
void collect_email_headers(MParcel *parcel, BuffControl *bc, RecipLink *recips);
void email_from_file_final_send(MParcel *parcel, BuffControl *bc,
                                RecipLink *recips, const HeaderField *headers);

void report_recipients(MParcel *parcel, RecipLink *rchain);
int end_of_email_message(const char *line, int line_len);

LJOutcomes line_judger(const char *line, int line_len);
void section_printer(MParcel *parcel, const char *line, int line_len);

/**
 * @brief The beginning of the three-step process of reading and sending emails.
 *
 * Each step involves a function that builds a data structure in stack
 * memory, then calls the next step.  When the emails are complete, the
 * memory is released as each function returns.
 */
void emails_from_file(MParcel *parcel)
{
   FILE *efile = ((MailerData*)parcel->data)->file_to_read;
   char buffer[1024];

   int use_new_mailer = 1;

   BuffControl bc;
   init_buff_control(&bc, buffer, sizeof(buffer), bc_file_reader, (void*)efile);

   while (!bc.reached_EOF)
   {
      if (use_new_mailer)
         mcb_send_email_simple(parcel, &bc, line_judger, section_printer);
      else
         collect_email_recipients(parcel, &bc);
   }
}

/**
 * @brief Step 2 of emails_from_file() process.
 */
void collect_email_recipients(MParcel *parcel, BuffControl *bc)
{
   const char *line;
   int line_len;

   char *tline;

   RecipLink *rl_root = NULL, *rl_tail = NULL, *rl_cur;
   int recipient_count = 0;
   int found_end_of_message = 0;

   while (bc_get_next_line(bc, &line, &line_len))
   {
      if (line_len == 1 && (*line == SECTION_DELIM  || *line == MESSAGE_DELIM))
      {
         if (*line == MESSAGE_DELIM)
            found_end_of_message = 1;

         break;
      }

      // Add for all types here, subtract if *line=='#'
      ++recipient_count;

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
            --recipient_count;
            break;
         default:
            // default value after memset struct to 0
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

   // Recipients collected, what's next?

   if (recipient_count && line_len==1 && (*line==SECTION_DELIM || *line==MESSAGE_DELIM))
   {
         if (*line == SECTION_DELIM)
            collect_email_headers(parcel, bc, rl_root);
         else if (*line == MESSAGE_DELIM)
         {
            mcb_send_email_new(parcel, rl_root, NULL, bc, line_judger, section_printer);
            /* email_from_file_final_send(parcel, bc, rl_root, NULL); */
         }
   }
   else  // Message will not be sent
   {
      if (!recipient_count)
         mcb_log_message(parcel, "No recipients for this email, which will now not be sent.", NULL);
      // If premature exit, warn and return without sending:
      else if (line_len == 0)
         mcb_log_message(parcel, "Incomplete email, not sent.", NULL);
      else
         mcb_log_message(parcel, "Unexpected exit from recipient-reading loop.", NULL);
      
      // Flush the rest of the message, if any:
      if (!found_end_of_message)
      {
         while (bc_get_next_line(bc, &line, &line_len))
            if (line_len==1 && *line==MESSAGE_DELIM)
               break;
      }
   }
}

/**
 * @brief Now having recipients, read any email headers into a HeaderField chain.
 */
void collect_email_headers(MParcel *parcel, BuffControl *bc, RecipLink *recips)
{
   const char *line;
   int line_len;

   const char *name, *value;
   int name_len, value_len;

   char *tline;

   HeaderField *h_root = NULL, *h_tail = NULL, *h_cur;
   FieldValue *v_tail = NULL, *v_cur;

   while (bc_get_next_line(bc, &line, &line_len))
   {
      if (line_len > 0)
      {
         if (*line == MESSAGE_DELIM)
            break;
         else if (*line == SECTION_DELIM)
         {
            if (line_len > 2 && *(line+1) == '#')
               mcb_set_multipart_flag(parcel);

            break;
         }
      }

      // Split line into name/value parts
      mcb_parse_header_line(line, &line[line_len], &name, &name_len, &value, &value_len);

      // For any name, create a new HeaderField link:
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

         // Copy name value to new stack memory array:
         tline = (char*)alloca(name_len+1);
         memcpy(tline, line, name_len);
         tline[name_len] = '\0';

         h_cur->name = tline;
         v_cur = NULL;
      }

      // Note that header field values may span multiple lines.
      // This code should accommodate that possibility.
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

         // Copy value line to new stack memory
         tline = (char*)alloca(value_len+1);
         memcpy(tline, value, value_len);
         tline[value_len] = '\0';

         v_cur->value = tline;
      }
   }

   mcb_send_email_new(parcel, recips, h_root, bc, line_judger, section_printer);
}

/**
 * @brief Send parsed email
 *
 * Separated out of collect_emailheaders() to provide a shortcut
 * that bypasses collect_email_headers().
 */
/* void email_from_file_final_send(MParcel *parcel, */
/*                                 BuffControl *bc, */
/*                                 RecipLink *recips, */
/*                                 const HeaderField *headers) */
/* { */
/*    const MailerData *md = (MailerData*)parcel->data; */

/*    if (md->fake_emailing) */
/*    { */
/*       printf("[36;1mPhantom sending of an email.[m\n"); */

/*       const char *line; */
/*       int line_len; */

/*       // flush to end-of-message */
/*       while (bc_get_next_line(bc, &line, &line_len)) */
/*          if (LJ_End_Message == (*line_judger)(line, line_len)) */
/*             break; */
/*    } */
/*    else */
/*       mcb_send_email_new(parcel, recips, headers, bc, line_judger, section_printer); */
/* } */

/***********************************/
/* Library SMTP Callback functions */
/***********************************/

/**
 * @brief Report the emailing results for each RCPT_TO address.
 *
 * This is a callback function that, if provided, the library calls
 * after each email.  The RecipLink chain then contains the status
 * of each address, whether it was accepted by the email server or
 * not.
 */
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

LJOutcomes line_judger(const char *line, int line_len)
{
   if (line_len > 0)
   {
      if (*line == MESSAGE_DELIM)
         return LJ_End_Message;
      else if (*line == SECTION_DELIM && (line_len == 1 || (line_len > 2 && *(line+1) =='#')))
         return LJ_End_Section;
   }

   return LJ_Continue;
}

void section_printer(MParcel *parcel, const char *line, int line_len)
{
   const char *ptr = line;
   const char *end = line+line_len;

   // '#' introduces a mime-type for the section
   while (ptr < end && *ptr != '#')
      ++ptr;

   if (*ptr=='#')
   {
      line_len -= (ptr - line);
      ++ptr;
      char *content_type = (char*)alloca(line_len);
      --line_len;
      memcpy(content_type, ptr, line_len);
      content_type[line_len] = '\0';
      
      mcb_send_mime_border(parcel, content_type, NULL);
   }
}

/**
 * @brief Callback function that **mailcb** uses to detect the end of a message
 */
int end_judger(const char *line, int line_len)
{
   return (line_len == 1 && *line == MESSAGE_DELIM);
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






/*************************************************************************/
/*                     POP mail reader processing                        */
/*************************************************************************/

/**
 * The email reading process is easier because the library handles
 * all of the memory allocation and the user of the library can
 * just consume that data.
 */

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


/**************************************************************************/
/*        Mailer program command line and config file processing          */
/**************************************************************************/
/**
 * @brief Begins task after processing CLI arguments and .conf file settings
 */
void talker_user(MParcel *parcel)
{
   if (mcb_is_opening_smtp(parcel))
      begin_smtp_conversation(parcel);
   else
      mcb_greet_pop_server(parcel);
}

/**
 * @brief Conditionally sets an execution flag.
 *
 * Used by *begin_after_read_config_attempt()* to set execution
 * flags according if the 
 */
int update_if_needed(const char *name,
                     const ri_Line *line,
                     const char **target,
                     const MParcel *parcel)
{
   if (*target == NULL)
      if (0 == strcmp(line->tag, name))
      {
         *target = line->value;
         return 1;
      }

   return 0;
}

/**
 * @brief Sets execution flags from a configuration file, if provided.
 *
 * This is a required stop between reading the command line arguments
 * and the execution of the program.  If a configuration file cannot be
 * found/read, the **root** parameter will be NULL, and execution will
 * begin with the values set on the command line.
 */
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

void write_guid(void)
{
   char buffer[37];
   mcb_make_guid(buffer, sizeof(buffer));
   puts(buffer);
}

void show_usage(void)
{
   const char* text = 
      "-a account to use\n"
      "-c config file path\n"
      "-f from email address\n"
      "-h host url\n"
      "-g generate version 4/variant 1 GUID\n"
      "-i email input file, '-' for stdin\n"
      "-l login name\n"
      "-p port number\n"
      "-r POP3 reader\n"
      "-q quiet, suppress error messages\n"
      "-s skip sending of emails\n"
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
               case 'g':  // generate random number (guid?)
                  write_guid();
                  goto abort_program;
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
               case 's':  // suppress emails 
                  mparcel.OnlySendEnvelope = 1;
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






