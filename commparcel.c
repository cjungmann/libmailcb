int get_size(const MParcel *mp) { return mp->cap_size; }
void set_size(MParcel *mp, const char *line) { mp->cap_size = atoi(line); }

int get_starttls(const MParcel *mp)    { return mp->cap_starttls != 0; }
void set_starttls(MParcel *mp, const char *line) { mp->cap_starttls = 1; }

int get_enhancedstatuscodes(const MParcel *mp) { return mp->cap_enhancedstatuscodes != 0; }
void set_enhancedstatuscodes(MParcel *mp, const char *line) { mp->cap_enhancedstatuscodes = 1; }

int get_8bitmime(const MParcel *mp) { return mp->cap_8bitmime != 0; }
void set_8bitmime(MParcel *mp, const char *line) { mp->cap_8bitmime = 1; }

int get_7bitmime(const MParcel *mp) { return mp->cap_7bitmime != 0; }
void set_7bitmime(MParcel *mp, const char *line) { mp->cap_7bitmime = 1; }

int get_pipelining(const MParcel *mp) { return mp->cap_pipelining != 0; }
void set_pipelining(MParcel *mp, const char *line) { mp->cap_pipelining = 1; }

int get_chunking(const MParcel *mp) { return mp->cap_chunking != 0; }
void set_chunking(MParcel *mp, const char *line) { mp->cap_chunking = 1; }

int get_smtputf8(const MParcel *mp) { return mp->cap_smtputf8 != 0; }
void set_smtputf8(MParcel *mp, const char *line) { mp->cap_smtputf8 = 1; }



int get_auth_plain(const MParcel *mp) { return mp->cap_auth_plain != 0; }
void set_auth_plain(MParcel *mp, const char *line) { mp->cap_auth_plain = 1; }

int get_auth_login(const MParcel *mp) { return mp->cap_auth_login != 0; }
void set_auth_login(MParcel *mp, const char *line) { mp->cap_auth_login = 1; }

int get_auth_gssapi(const MParcel *mp) { return mp->cap_auth_gssapi != 0; }
void set_auth_gssapi(MParcel *mp, const char *line) { mp->cap_auth_gssapi = 1; }

int get_auth_digest_md5(const MParcel *mp) { return mp->cap_auth_digest_md5 != 0; }
void set_auth_digest_md5(MParcel *mp, const char *line) { mp->cap_auth_digest_md5 = 1; }

int get_auth_md5(const MParcel *mp) { return mp->cap_auth_md5 != 0; }
void set_auth_md5(MParcel *mp, const char *line) { mp->cap_auth_md5 = 1; }

int get_auth_cram_md5(const MParcel *mp) { return mp->cap_auth_cram_md5 != 0; }
void set_auth_cram_md5(MParcel *mp, const char *line) { mp->cap_auth_cram_md5 = 1; }

int get_auth_oauth10a(const MParcel *mp) { return mp->cap_auth_oauth10a != 0; }
void set_auth_oauth10a(MParcel *mp, const char *line) { mp->cap_auth_oauth10a = 1; }

int get_auth_oauthbearer(const MParcel *mp) { return mp->cap_auth_oauthbearer != 0; }
void set_auth_oauthbearer(MParcel *mp, const char *line) { mp->cap_auth_oauthbearer = 1; }

void set_auth(MParcel *mp, const char *line)
{
   
}
