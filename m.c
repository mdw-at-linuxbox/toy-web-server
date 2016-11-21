#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#include "civetweb.h"

struct myhttpd_data {
	int dummy;
};

int rc;

int
my_begin_request(struct mg_connection *conn)
{
	struct mg_request_info const *req_info = mg_get_request_info(conn);
	struct myhttpd_data *me = (struct myhttpd_data*)(req_info->user_data);
	int i;
	char const *cl = 0;

	fprintf (stdout, "method: %s\n", req_info->request_method);
	fprintf (stdout, "uri: %s\n", req_info->uri);
	if (req_info->query_string)
		fprintf (stdout, "qs: %s\n", req_info->query_string);
	fprintf (stdout, "user: %s\n", req_info->remote_user);
	for (i = 0; i < req_info->num_headers; ++i) {
		if (!strncasecmp("content-length",
				req_info->http_headers[i].name, 14))
			cl = req_info->http_headers[i].value;
		fprintf (stdout, "hd%d: %s=%s\n", i,
			req_info->http_headers[i].name,
			req_info->http_headers[i].value);
	}
	if (!strcmp(req_info->request_method, "POST")) {
		char buf[1024];
		char *ep = 0;
		int c, totlen, sofar;
		totlen = cl ? strtol(cl, &ep, 0) : -1;
		if (cl)
			fprintf(stdout, "reading content: %d\n", totlen);
		for (sofar = 0;;sofar += c) {
			if (totlen >= 0 && sofar >= totlen) break;
			c = totlen - sofar;
			if (c > sizeof buf) c = sizeof buf;
			c = mg_read(conn, buf, c);
			if (c <= 0) break;
			fprintf (stdout, "dt%d-%d: %.*s\n",
				sofar, sofar+c, c, buf);
		}
	}
	return 0;
}

int
my_log_message(const struct mg_connection *conn, const char *buf)
{
	fprintf (stdout, "m %s\n", buf);
	return 0;
}

int
my_log_access(const struct mg_connection *conn, const char *buf)
{
	fprintf (stdout, "a %s\n", buf);
	return 0;
}

struct mg_callbacks cb[1] = {{
	begin_request: my_begin_request,
	log_message: my_log_message,
	log_access: my_log_access,
}};

int
main(int ac, char **av)
{
	struct mg_context *ctx;
	struct myhttpd_data ud[1];
	char *options[40], **cpp;

	cpp = options;
	*cpp++ = "decode_url", *cpp++ = "no";
	*cpp++ = "enable_keep_alive", *cpp++ = "yes";
	*cpp++ = "validate_http_method", *cpp++ = "no";
	*cpp++ = "canonicalize_url_path", *cpp++ = "no";
	*cpp++ = "listening_ports", *cpp++ = "5080";

	ctx = mg_start(cb, ud, (const char **) options);
	for (;;) {
		pause();
	}
	exit(rc);
}
