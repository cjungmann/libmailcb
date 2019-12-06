#include <stdio.h>
#include <alloca.h>
#include <unistd.h>    // for close() function

#include "mailcb.h"

void test_itoa_buff(int value, int base)
{
   int buff_len = digits_in_base(value, base) + 1;
   char *buffer = (char*)alloca(buff_len);

   printf("%d, in base %d, has %d digits.\n", value, base, digits_in_base(value,base));
   if (itoa_buff(value, base, buffer, buff_len))
      printf("Conversion from %d in base %d is %s.\n", value, base, buffer);
   else
      printf("Conversion buffer overflow.\n");
}

void test_connection(void)
{
   int osocket = get_connected_socket("smtp.gmail.com", 587);

   if (osocket >= 0)
   {
      printf("Got an open, connected socket.\n");
      close(osocket);
   }
   else
      printf("Failed to get an open, connected socket.\n");
}

void test_hello(MParcel *mparcel)
{
   int osocket = get_connected_socket(mparcel->host_url, mparcel->host_port);

   if (osocket >= 0)
   {
      greet_server(mparcel, osocket);
      close(osocket);
   }
   else
      printf("Failed to get an open, connected socket.\n");
}

int main(int argc, const char** argv)
{
   MParcel mparcel;
   memset(&mparcel, 0, sizeof(mparcel));
   mparcel.host_port = 25;

   // process command line arguments:
   const char **cur_arg = argv;
   const char **end_arg = cur_arg + argc;
   const char *str;

   while (cur_arg < end_arg)
   {
      str = *cur_arg;
      if (*str == '-')
      {
         while (*++str)
         {
            switch(*str)
            {
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
               case 'q':  // suppress error messages
               default:
                  break;
            }
         }
      }

     continue_next_arg:
      ++cur_arg;
   }

   
   // Request password if not provided:



      /* test_connection(); */
      test_hello(&mparcel);
      

   return 0;
}




