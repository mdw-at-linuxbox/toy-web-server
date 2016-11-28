struct myhttpd_data {
	int dummy;
};

struct mybufs {
	struct mybufs *next;
	char data[1024];
	int len;
};

void free_postdata(struct mybufs *);
void append_postdata(struct mybufs **, char *, int);
void append_postdata_format(struct mybufs **, char *, ...);
int compute_postdata_len(struct mybufs *);
void copy_postdata_to_mg(struct mg_connection *, struct mybufs *);
void copy_postdata_to_buf(char *, int, struct mybufs *);
void read_postdata(struct mybufs **, struct mg_connection *conn);
const char * my_get_response_code_text(int);
void my_gmt_time_string(char *, int, time_t *);
