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

void test_advise(void)
{
   MParcel p;
   memset(&p, 0, sizeof(p));
   p.verbose = 1;

   advise_message(&p, "This ", "is ",  "a ", "broken-up ", "string ", NULL);
}


int main(int argc, const char** argv)
{
   test_connection();
   test_advise();
   return 0;
}




