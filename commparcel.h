#ifndef COMMPARCEL_H
#define COMMPARCEL_H

typedef void (*Set_Cap_Func)(MParcel *mp, const char *line, int len);
typedef struct _cap_string
{
   const char   *str;
   int          len;
   Set_Cap_Func set_cap;
} CapString;


void clear_smtp_caps(MParcel *mp);

int get_size(const MParcel *mp);
void set_size(MParcel *mp, const char *line, int len);

int get_starttls(const MParcel *mp);
void set_starttls(MParcel *mp, const char *line, int len);

int get_enhancedstatuscodes(const MParcel *mp);
void set_enhancedstatuscodes(MParcel *mp, const char *line, int len);

int get_8bitmime(const MParcel *mp);
void set_8bitmime(MParcel *mp, const char *line, int len);

int get_7bitmime(const MParcel *mp);
void set_7bitmime(MParcel *mp, const char *line, int len);

int get_pipelining(const MParcel *mp);
void set_pipelining(MParcel *mp, const char *line, int len);

int get_chunking(const MParcel *mp);
void set_chunking(MParcel *mp, const char *line, int len);

int get_smtputf8(const MParcel *mp);
void set_smtputf8(MParcel *mp, const char *line, int len);



int get_auth_plain(const MParcel *mp);
void set_auth_plain(MParcel *mp, const char *line, int len);

int get_auth_login(const MParcel *mp);
void set_auth_login(MParcel *mp, const char *line, int len);

int get_auth_gssapi(const MParcel *mp);
void set_auth_gssapi(MParcel *mp, const char *line, int len);

int get_auth_digest_md5(const MParcel *mp);
void set_auth_digest_md5(MParcel *mp, const char *line, int len);

int get_auth_md5(const MParcel *mp);
void set_auth_md5(MParcel *mp, const char *line, int len);

int get_auth_cram_md5(const MParcel *mp);
void set_auth_cram_md5(MParcel *mp, const char *line, int len);

int get_auth_oauth10a(const MParcel *mp);
void set_auth_oauth10a(MParcel *mp, const char *line, int len);

int get_auth_oauthbearer(const MParcel *mp);
void set_auth_oauthbearer(MParcel *mp, const char *line, int len);

int get_auth_xoauth(const MParcel *mp);
void set_auth_xoauth(MParcel *mp, const char *line, int len);

int get_auth_xoauths(const MParcel *mp);
void set_auth_xoauth2(MParcel *mp, const char *line, int len);

void set_auth(MParcel *mp, const char *line, int len);



#endif
