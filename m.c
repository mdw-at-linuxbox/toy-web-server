#include <pthread.h>
#include "civetweb.h"
#include <stdlib.h>
#include <stdio.h>

struct myhttpd_data {
	int dummy;
};

int rc;

int
my_begin_request(struct mg_connection *conn)
{
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
	char *options[8], **cpp;

	*cpp++ = "decode_url", *cpp++ = "no";
	*cpp++ = "enable_keep_alive", *cpp++ = "yes";
	*cpp++ = "validate_http_method", *cpp++ = "no";
	*cpp++ = "canonicalize_url_path", *cpp++ = "no";
	*cpp++ = "listening_ports", *cpp++ = "5080";

	ctx = mg_start(cb, ud, (const char **) options);
	exit(rc);
}
