#include <string.h>      // for memset()
#include "socktalk.h"
#include "mailcb.h"
#include "mailcb_internal.h"

#define MESSAGE_DELIM '\f'
#define SECTION_DELIM '\v'

typedef struct _closure_simple_send_email
{
   MParcel             *parcel;
   BuffControl         *bc;
   EmailLineJudge      line_judger;
   EmailSectionPrinter section_printer;
   RecipLink           *recipients;    
   const HeaderField   *fields;
} SSEClosure;

void int_flush_to_end(SSEClosure *ssec);
void int_collect_recipients(SSEClosure *ssec);
void int_collect_headers(SSEClosure *ssec);

void mcb_basic_section_printer(MParcel *parcel, const char *line, int line_len)
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
      
      mcb_smtp_send_mime_border(parcel, content_type, NULL);
   }
}

LJOutcomes mcb_basic_line_judger(const char *line, int line_len)
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
   

void int_flush_to_end(SSEClosure *ssec)
{
   const char *line;
   int line_len;
   
   while (bc_get_next_line(ssec->bc, &line, &line_len))
      if (LJ_End_Message == (*ssec->line_judger)(line, line_len))
         break;
}

void int_collect_recipients(SSEClosure *ssec)
{
   const char *line;
   int line_len;

   char *tline;

   RecipLink *rl_root = NULL, *rl_tail = NULL, *rl_cur;
   int recipient_count = 0;

   LJOutcomes line_judgement;

   while (bc_get_next_line(ssec->bc, &line, &line_len))
   {
      if (LJ_Continue != (line_judgement=(*ssec->line_judger)(line, line_len)))
         break;
      
      // Add for all types here, subtract later if *line=='#'
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
         // For prefixed recipients, trim the prefix before copying
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
   }  // end while(bc_get_next_line())

   // Proceed based on why the while loop ended:
   if (line_judgement == LJ_End_Section)
   {
      if (recipient_count > 0)
      {
         ssec->recipients = rl_root;
         int_collect_headers(ssec);
      }
      else
      {
         mcb_log_message(ssec->parcel,
                         "No recipients for this email, which will now not be sent.",
                         NULL);

         int_flush_to_end(ssec);
      }
   }
   else if (line_judgement == LJ_End_Message)
   {
      mcb_log_message(ssec->parcel,
                      "No recipients for this email, which will now not be sent.",
                      NULL);
      // allow to return without sending anything
   }
   else
   {
      mcb_log_message(ssec->parcel, "Unexpected outcome while reading recipients.", NULL);
      int_flush_to_end(ssec);
   }
}

void int_collect_headers(SSEClosure *ssec)
{
   const char *line;
   int line_len;

   const char *name, *value;
   int name_len, value_len;

   char *tline;

   HeaderField *h_root = NULL, *h_tail = NULL, *h_cur;
   FieldValue *v_tail = NULL, *v_cur;

   LJOutcomes line_judgement;

   while (bc_get_next_line(ssec->bc, &line, &line_len))
   {
      if (LJ_Continue != (line_judgement=(*ssec->line_judger)(line, line_len)))
         break;

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
         v_cur = (FieldValue*)alloca(sizeof(FieldValue));
         memset(v_cur, 0, sizeof(FieldValue));

         // Copy value line to new stack memory
         tline = (char*)alloca(value_len+1);
         memcpy(tline, value, value_len);
         tline[value_len] = '\0';

         v_cur->value = tline;

         if (v_tail)
         {
            v_tail->next = v_cur;
            v_tail = v_cur;
         }
         else
            h_cur->value = v_tail = v_cur;
      }
   }

   mcb_send_email_new(ssec->parcel, ssec->recipients, h_root, ssec->bc, ssec->line_judger, ssec->section_printer);
}

void mcb_send_email_simple(MParcel *parcel,
                           BuffControl *bc,
                           EmailLineJudge line_judger,
                           EmailSectionPrinter section_printer)
{
   SSEClosure ssec;
   memset(&ssec, 0, sizeof(ssec));
   ssec.parcel          = parcel;
   ssec.bc              = bc;
   ssec.line_judger     = line_judger;
   ssec.section_printer = section_printer;

   int_collect_recipients(&ssec);
}
