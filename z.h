typedef struct zxid_conf zxid_conf;
typedef struct zxid_ses zxid_ses;
int zxid_mini_httpd_filter(zxid_conf*, struct mg_connection *,
	struct mybufs *, zxid_ses **);
