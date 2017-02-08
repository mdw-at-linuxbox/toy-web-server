struct toybufs {
	struct toybufs *next;
	char data[1024];
	int len;
};

void free_postdata(struct toybufs *);
void append_postdata(struct toybufs **, char *, int);
void prefix_postdata(struct toybufs **, char *, int);
void append_postdata_format(struct toybufs **, char *, ...);
void prefix_postdata_format(struct toybufs **, char *, ...);
int compute_postdata_len(struct toybufs *);
void copy_postdata_to_buf(char *, int, struct toybufs *);
const char * my_get_response_code_text(int);
void my_gmt_time_string(char *, int, time_t *);
