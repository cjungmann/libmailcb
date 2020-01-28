#include <string.h>  // for memcpy, memset.
#include <readini.h>
#include "mailcb.h"

/**
 * Create a file, simple_smtp.conf that looks like this, with the
 * values changed according to your specific email server:
 * [my_section]
 *   host     smtp.gmail.com
 *   port     587
 *   use_tls  on
 *   from     me@gmail.com
 *   user     me@gmail.com
 *   password gmail_password
 */

const char* email_addresses[] = {
   "chuck@cpjj.net",
   "chuckj60@gmail.com",
   "chuckjungmann@gmail.com",
   NULL
};

const char* email_headers[] = {
   "Subject: Sample email subject",
   NULL
};


typedef void (*Recips_Return)(RecipLink *recips_chain, void* data);
typedef void (*Headers_Return)(HeaderField *headers_chain, RecipLink *recips_chain, void* data);

void make_recips_from_array(const char **addresses, Recips_Return callback, void* data);
void make_headers_from_array(const char **headers, RecipLink *recips_chain, Headers_Return callback, void* data);

void make_recips_from_array(const char **addresses, Recips_Return callback, void* data)
{
   const char **ptr = addresses;
   RecipLink *root, *tail, *cur;
   const char *address;

   while (*ptr)
   {
      // Make chain link:
      cur = (RecipLink*)alloca(sizeof(RecipLink));
      memset(cur, 0, sizeof(RecipLink));

      address = *ptr;

      // Tag address according to prefix
      switch(*address)
      {
         case '#':
            cur->rtype = RT_SKIP;
            ++address;
            break;
         case '+':
            cur->rtype = RT_CC;
            ++address;
            break;
         case '-':
            cur->rtype = RT_BCC;
            ++address;
            break;
         default:
            break;
      }

      // No need to copy string data that will remain valid for callback:
      cur->address = address;

      // Establish or add link to the chain:
      if (tail)
      {
         tail->next = cur;
         tail = cur;
      }
      else
         root = tail = cur;

      ++ptr;
   }

   (*callback)(root, data);
}

void make_headers_from_array(const char **headers, RecipLink *recips_chain, Headers_Return callback, void* data)
{
   const char **ptr = headers;
   HeaderField *h_root=NULL, *h_tail=NULL, *h_cur;
   FieldValue *v_root=NULL, *v_tail=NULL, *v_cur;

   char *twork;
   const char *name, *value;
   int name_len, value_len;

   while (*ptr)
   {
      mcb_parse_header_line(*ptr, *ptr + strlen(*ptr), &name, &name_len, &value, &value_len);

      if (name_len)
      {
         v_root = v_tail = NULL;

         h_cur = (HeaderField*)alloca(sizeof(HeaderField));
         memset(h_cur, 0, sizeof(HeaderField));

         // Work with non-const working variable before assigning to const char*
         twork = (char*)alloca(name_len+1);
         memcpy(twork, name, name_len);
         twork[name_len] = '\0';

         h_cur->name = twork;

         if (h_tail)
         {
            h_tail->next = h_cur;
            h_tail = h_cur;
         }
         else
            h_root = h_tail = h_cur;
      }

      if (value_len)
      {
         v_cur = (FieldValue*)alloca(sizeof(FieldValue));
         memset(v_cur, 0, sizeof(FieldValue));

         twork = (char*)alloca(value_len+1);
         memcpy(twork, value, value_len);
         twork[value_len] = '\0';

         v_cur->value = twork;

         if (v_tail)
            v_tail->next = v_cur;
         else
         {
            v_root = v_tail = v_cur;
            h_cur->value = v_root;
         }
      }
      
      ++ptr;
   }

   (*callback)(h_root, recips_chain, data);
}

void print_header_link(HeaderField *header_link)
{
   FieldValue *fvalue = header_link->value;
   printf("%s:", header_link->name);

   if (fvalue)
   {
      while (fvalue)
      {
         if (fvalue != header_link->value)
            printf("\t");

         printf("%s\n", fvalue->value);

         fvalue = fvalue->next;
      }
   }
   else
      printf("\n");
}



/*******************************************************
 * Support functions not directly used by the libraries.
 *******************************************************/
int tag_matches(const ri_Line *line, const char *tag_name)
{
   return strcmp(line->tag, tag_name) == 0;
}

int value_matches(const ri_Line *line, const char *value)
{
   return strcmp(line->value, value) == 0;
}


/**
 * Callback functions used by the libraries
 */

// Callback for readini.so : ri_read_file()
void configure_parcel_from_config(const ri_Section *root, void *data);

LJOutcomes line_judger(const char *line, int line_len);
void section_printer(MParcel *parcel, const char *line, int line_len);

void report_recipients(MParcel *parcel, RecipLink *chain);


/**
 * Callback functions for local functions
 */

void use_headers_chain(HeaderField *headers_chain, RecipLink *recips_chain, void* data)
{
   HeaderField *hlink = headers_chain;
   RecipLink   *rlink = recips_chain;
   /* MParcel *parcel = (MParcel*)data; */

   while (rlink)
   {
      printf("Address: %s.\n", rlink->address);
      rlink = rlink->next;
   }

   while (hlink)
   {
      print_header_link(hlink);
      hlink = hlink->next;
   }
}

void use_recips_chain(RecipLink *chain, void *data)
{
   make_headers_from_array(email_headers, chain, use_headers_chain, data);

}


void begin_smtp_conversation(MParcel *parcel)
{
   printf("About to send some emails!\n");

   make_recips_from_array(email_addresses, use_recips_chain, parcel);
}


void configure_parcel_from_config(const ri_Section *root, void *data)
{
   if (root)
   {
      MParcel *parcel = (MParcel*)data;

      const ri_Line *curline = root->lines;
      while (curline)
      {
         if (tag_matches(curline, "host"))
            parcel->host_url = curline->value;
         else if (tag_matches(curline, "port"))
            parcel->host_port = atoi(curline->value);
         else if (tag_matches(curline, "use_tls"))
         {
            if (value_matches(curline, "on"))
               parcel->starttls = 1;
         }
         else if (tag_matches(curline, "from"))
            parcel->from = curline->value;
         else if (tag_matches(curline, "user"))
            parcel->login = curline->value;
         else if (tag_matches(curline, "password"))
            parcel->password = curline->value;

         curline = curline->next;
      }

      begin_smtp_conversation(parcel);
   }
}

int main(int argc, const char **argv)
{
   MParcel parcel;
   memset(&parcel, 0, sizeof(parcel));

   // Prepare the MParcel object.  One way is to use
   // readini library, but you can set the fields with
   // other tools or directly.

   
   // Hard-code the email credentials by changing to "if (1)"
   // and setting your particular email settings below.
   if (0)
   {
      // The minimum MParcel properties that must be set:

      // Internet address values
      parcel.host_url  = "me@gmail.com";
      parcel.host_port = 587;
      parcel.starttls  = 1;
      // Account login values
      parcel.login     = "me@gmail.com";  // 
      parcel.password  = "mypassword";
      // From whom the emails will come:
      parcel.from      = "me@gmail.com";

      begin_smtp_conversation(&parcel);
   }
   else
   {
      // By default, read credentials from a configuration file:
      ri_read_file("./simple_smtp.conf", configure_parcel_from_config, (void*)&parcel);
   }
}
