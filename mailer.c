#include <stdio.h>
#include <alloca.h>
#include <unistd.h>    // for close() function

#include "mailcb.h"
#include <readini.h>

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

void server_notice_html(MParcel *parcel)
{
   printf("Got notice from MailCB.  Sending HTML message.\n");
   mcb_send_email(parcel,
                  // Recipients:
                  (const char*[]){"chuck@cpjj.net", "chuckjungmann@gmail.com", NULL},
                  // Headers
                  (const char*[]){"Subject: SMTP Server Debugging with HTML message",
                        "MIME-Version: 1.0",
                        "Content-Type: text/html; charset=\"UTF-8\"",
                        NULL},
                  // Message body
                  "<html>\n"
                  "<body>\n"
                  "<p>\n"
                  "</p>\n"
                  "The message is required in order to make a complete email\n"
                  "package.  Please don't misinterpret my intentions.  I only\n"
                  "want to test a bulk email sender.\n"
                  "</body>\n"
                  "</html>");
}

int pop_message_receiver(PopClosure *popc, const HeaderField *fields)
{

   const HeaderField *ptr;
   int str_len,  max_name_len = 0;

   ptr = fields;
   while (ptr)
   {
      str_len = strlen(ptr->name);
      if (str_len > max_name_len)
         max_name_len = str_len;

      ptr = ptr->next;
   }



   printf("\n[34;1m");
   printf("Max name length is %d.\n", max_name_len);
   ptr = fields;
   while (ptr)
   {
      printf("%*s: %s\n", max_name_len, ptr->name, ptr->value);
      ptr = ptr->next;
   }
   printf("[m\n");
   return 1;
}

void server_notice_text(MParcel *parcel)
{
   printf("Got notice from MailCB.\n");

   mcb_send_email(parcel,
                  (const char*[]){"chuck@cpjj.net", NULL},
                  (const char*[]){"Subject: SMTP Server Debugging", NULL},
                  "The message is required in order to make a complete email\n"
                  "package.  Please don't misinterpret my intentions.  I only\n"
                  "want to test a bulk email sender.");
}

void begin_smtp_conversation(MParcel *parcel)
{
   if (authorize_smtp_session(parcel))
   {
      server_notice_text(parcel);
      server_notice_html(parcel);
   }
}

void talker_user(MParcel *parcel)
{
   mcb_advise_message(parcel, "Entered the talker_user function.", NULL);

   if (is_opening_smtp(parcel))
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
      "-l login name\n"
      "-p port number\n"
      "-r POP3 reader\n"
      "-q quiet, supress error messages\n"
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


   // process command line arguments:
   const char **cur_arg = argv;
   const char **end_arg = cur_arg + argc;
   const char *str;

   const char *config_file_path = "./mailer.conf";

   while (cur_arg < end_arg)
   {
      str = *cur_arg;
      if (*str == '-')
      {
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

  abort_program:
   return 0;
}


