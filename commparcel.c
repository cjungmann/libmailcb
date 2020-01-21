#include "mailcb.h"
#include <ctype.h>   // for isspace()
#include <string.h>  // for memset, memcpy, etc

#include "commparcel.h"

CapString authstrings[] = {
   {"PLAIN",        5, set_auth_plain},
   {"LOGIN",        5, set_auth_login},
   {"GSSAPI",       6, set_auth_gssapi},
   {"DIGEST-MD5",  10, set_auth_digest_md5},
   {"MD5",          3, set_auth_md5},
   {"CRAM-MD5",     8, set_auth_cram_md5},
   {"OAUTH10A",     8, set_auth_oauth10a},
   {"OAUTHBEARER", 11, set_auth_oauthbearer},
   {"XOAUTH",       6, set_auth_xoauth},
   {"XOAUTH2",      7, set_auth_xoauth2}
};

int authstrings_count = sizeof(authstrings) / sizeof(CapString);
const CapString *authstring_end = &authstrings[sizeof(authstrings) / sizeof(CapString)];

void clear_smtp_caps(MParcel *mp) { memset(&mp->caps, 0, sizeof(SmtpCaps)); }

int get_size(const MParcel *mp) { return mp->caps.cap_size; }
void set_size(MParcel *mp, const char *line, int len) { mp->caps.cap_size = atoi(line); }

int get_starttls(const MParcel *mp)    { return mp->caps.cap_starttls != 0; }
void set_starttls(MParcel *mp, const char *line, int len) { mp->caps.cap_starttls = 1; }

int get_enhancedstatuscodes(const MParcel *mp) { return mp->caps.cap_enhancedstatuscodes != 0; }
void set_enhancedstatuscodes(MParcel *mp, const char *line, int len) { mp->caps.cap_enhancedstatuscodes = 1; }

int get_8bitmime(const MParcel *mp) { return mp->caps.cap_8bitmime != 0; }
void set_8bitmime(MParcel *mp, const char *line, int len) { mp->caps.cap_8bitmime = 1; }

int get_7bitmime(const MParcel *mp) { return mp->caps.cap_7bitmime != 0; }
void set_7bitmime(MParcel *mp, const char *line, int len) { mp->caps.cap_7bitmime = 1; }

int get_pipelining(const MParcel *mp) { return mp->caps.cap_pipelining != 0; }
void set_pipelining(MParcel *mp, const char *line, int len) { mp->caps.cap_pipelining = 1; }

int get_chunking(const MParcel *mp) { return mp->caps.cap_chunking != 0; }
void set_chunking(MParcel *mp, const char *line, int len) { mp->caps.cap_chunking = 1; }

int get_smtputf8(const MParcel *mp) { return mp->caps.cap_smtputf8 != 0; }
void set_smtputf8(MParcel *mp, const char *line, int len) { mp->caps.cap_smtputf8 = 1; }



/** Authorization specific settings */

int get_auth(const MParcel *mp) { return mp->caps.cap_auth_any > 0; }
void add_auth(MParcel *mp) { mp->caps.cap_auth_any++; }

int get_auth_plain(const MParcel *mp) { return mp->caps.cap_auth_plain != 0; }
void set_auth_plain(MParcel *mp, const char *line, int len) { add_auth(mp); mp->caps.cap_auth_plain = 1; }

int get_auth_login(const MParcel *mp) { return mp->caps.cap_auth_login != 0; }
void set_auth_login(MParcel *mp, const char *line, int len) { add_auth(mp); mp->caps.cap_auth_login = 1; }

int get_auth_gssapi(const MParcel *mp) { return mp->caps.cap_auth_gssapi != 0; }
void set_auth_gssapi(MParcel *mp, const char *line, int len) { add_auth(mp); mp->caps.cap_auth_gssapi = 1; }

int get_auth_digest_md5(const MParcel *mp) { return mp->caps.cap_auth_digest_md5 != 0; }
void set_auth_digest_md5(MParcel *mp, const char *line, int len) { add_auth(mp); mp->caps.cap_auth_digest_md5 = 1; }

int get_auth_md5(const MParcel *mp) { return mp->caps.cap_auth_md5 != 0; }
void set_auth_md5(MParcel *mp, const char *line, int len) { add_auth(mp); mp->caps.cap_auth_md5 = 1; }

int get_auth_cram_md5(const MParcel *mp) { return mp->caps.cap_auth_cram_md5 != 0; }
void set_auth_cram_md5(MParcel *mp, const char *line, int len) { add_auth(mp); mp->caps.cap_auth_cram_md5 = 1; }

int get_auth_oauth10a(const MParcel *mp) { return mp->caps.cap_auth_oauth10a != 0; }
void set_auth_oauth10a(MParcel *mp, const char *line, int len) { add_auth(mp); mp->caps.cap_auth_oauth10a = 1; }

int get_auth_oauthbearer(const MParcel *mp) { return mp->caps.cap_auth_oauthbearer != 0; }
void set_auth_oauthbearer(MParcel *mp, const char *line, int len) { add_auth(mp); mp->caps.cap_auth_oauthbearer = 1; }

int get_auth_xoauth(const MParcel *mp) { return mp->caps.cap_auth_xoauth != 0; }
void set_auth_xoauth(MParcel *mp, const char *line, int len) { add_auth(mp); mp->caps.cap_auth_xoauth = 1; }

int get_auth_xoauth2(const MParcel *mp) { return mp->caps.cap_auth_xoauth2 != 0; }
void set_auth_xoauth2(MParcel *mp, const char *line, int len) { add_auth(mp); mp->caps.cap_auth_xoauth2 = 1; }

void set_auth(MParcel *mp, const char *line, int len)
{
   const char *end = line + len + 1; // make sure to include the terminating \r or \0
   const char *ptr = line + 5;       // Skip "AUTH "
   const char *cur = ptr;
   while (ptr < end)
   {
      if (isspace(*ptr))
      {
         // find matching authorization struct:
         const CapString *curauth = authstrings;
         while (0 != strncmp(cur, curauth->str, curauth->len))
            ++curauth;

         char *temp = (char*)(alloca(ptr - cur));
         strncpy(temp, cur, ptr - cur);
         temp[ptr-cur] = '\0';

         if (curauth < authstring_end)
            (*curauth->set_cap)(mp, cur, ptr-cur);
         else
            mcb_log_message(mp, "Unexpected authorization protocol: ", temp, ".", NULL);

         // Start next authorization protocol with character after the space:
         // Skip past the space:
         cur = ++ptr;
      }
      else
         ++ptr;
   }
}
