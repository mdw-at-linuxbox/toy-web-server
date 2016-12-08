struct mybufs {
	struct mybufs *next;
	char data[1024];
	int len;
};

void free_postdata(struct mybufs *);
void append_postdata(struct mybufs **, char *, int);
void prefix_postdata(struct mybufs **, char *, int);
void append_postdata_format(struct mybufs **, char *, ...);
void prefix_postdata_format(struct mybufs **, char *, ...);
int compute_postdata_len(struct mybufs *);
void copy_postdata_to_buf(char *, int, struct mybufs *);
const char * my_get_response_code_text(int);
void my_gmt_time_string(char *, int, time_t *);
