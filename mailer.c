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
         section = ri_get_section(root, acct);
         if (section)
         {
            line = section->lines;
            while (line)
            {
               if (update_if_needed("host", line, &parcel->host_url, parcel))
                  goto next_line;

               if (update_if_needed("from", line, &parcel->login, parcel))
                  goto next_line;

               if (update_if_needed("user", line, &parcel->user, parcel))
                  goto next_line;

               if (update_if_needed("password", line, &parcel->password, parcel))
                  goto next_line;

               if (0 == parcel->host_port && 0 == strcmp(line->tag, "port"))
               {
                  parcel->host_port = atoi(line->value);
                  goto next_line;
               }

               else if (0 == parcel->starttls
                        && 0 == strcmp(line->tag, "use_tls")
                        && 0 == strcmp(line->value, "on"))
               {
                  parcel->starttls = 1;
                  goto next_line;
               }

              next_line:
               line = line->next;
            }
         }
      }
   }

   int osocket = get_connected_socket(parcel->host_url, parcel->host_port);
   if (osocket)
   {
      advise_message(parcel, "Socket opened, about to begin conversation.", NULL);
      greet_server(parcel, osocket);
      close(osocket);
   }


   /* test_connection(); */
   /* test_hello(parcel); */

}

int main(int argc, const char** argv)
{
   MParcel mparcel;
   memset(&mparcel, 0, sizeof(mparcel));

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
               case 'c':  // config file
                  if (cur_arg + 1 < end_arg)
                  {
                     config_file_path = *++cur_arg;
                     goto continue_next_arg;
                  }
                  break;
               case 'a':  // config account to use
                  if (cur_arg + 1 < end_arg)
                  {
                     mparcel.account = *++cur_arg;
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
               case 'p':  // port
                  if (cur_arg + 1 < end_arg)
                  {
                     mparcel.host_port = atoi(*++cur_arg);
                     goto continue_next_arg;
                  }
                  break;
               case 'u':  // user
                  if (cur_arg + 1 < end_arg)
                  {
                     mparcel.user = *++cur_arg;
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
               case 'w':  // passWord
                  if (cur_arg + 1 < end_arg)
                  {
                     mparcel.password = *++cur_arg;
                     goto continue_next_arg;
                  }

               case 't':   // tls
                  mparcel.starttls = 1;
                  break;
               case 'v':  // verbose messages
                  mparcel.verbose = 1;
                  break;
               case 'q':  // suppress error messages
                  mparcel.quiet = 1;
                  break;

               default:
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
      advise_message(&mparcel, "About to open config file \"", config_file_path, "\"", NULL);
      ri_read_file(config_file_path,
                   begin_after_read_config_attempt,
                   (void*)&mparcel);
   }
   else
   {
      advise_message(&mparcel, "Failed to find configuration file.", NULL);
      begin_after_read_config_attempt(NULL, (void*)&mparcel);
   }

   return 0;
}


