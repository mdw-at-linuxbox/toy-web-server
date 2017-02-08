typedef struct zxid_conf zxid_conf;
typedef struct zxid_ses zxid_ses;
int zxid_mini_httpd_filter(zxid_conf*, struct mg_connection *,
	struct toybufs *, zxid_ses **);
int zxid_pool2env(zxid_conf*, zxid_ses*, char **, int, char **);
