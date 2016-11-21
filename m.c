#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "civetweb.h"

struct myhttpd_data {
	int dummy;
};

struct mybufs {
	struct mybufs *next;
	char data[1024];
	int len;
};

int rc;

void
free_postdata(struct mybufs *postdata)
{
	struct mybufs *next;
	for (; postdata; postdata = next) {
		next = postdata->next;
		free(postdata);
	}
}

void
append_postdata(struct mybufs **postdata, char *buf, int len)
{
	struct mybufs *thisp, **nextp;
	int c;
	thisp = 0;
	for (nextp = postdata; *nextp; nextp = &thisp->next) {
		if (!*nextp) break;
		thisp = *nextp;
	}
	if (thisp && thisp->len < sizeof thisp->data) {
		c = sizeof thisp->data - thisp->len;
		if (c > len) c = len;
		memcpy(thisp->data + thisp->len, buf, c);
		thisp->len += c;
		buf += c;
		len -= c;
	}
	for (; len; buf += c, len -= c) {
		thisp = malloc(sizeof *thisp);
		memset(thisp, 0, sizeof *thisp);
		c = len;
		if (c > sizeof thisp->data) c = sizeof thisp->data;
		memcpy(thisp->data, buf, c);
		thisp->next = 0;
		thisp->len = c;
		*nextp = thisp;
		nextp = &thisp->next;
	}
}

void
append_postdata_format(struct mybufs **postdata, char *fmt, ...)
{
	char buf[65536];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof buf, fmt, ap);
	va_end(ap);
	append_postdata(postdata, buf, strlen(buf));
}

int
compute_postdata_len(struct mybufs *postdata)
{
	struct mybufs *thisp;
	int r;
	r = 0;
	for (thisp = postdata; thisp; thisp = thisp->next) {
		r += thisp->len;
	}
	return r;
}

void
copy_postdata_to_mg(struct mg_connection *conn, struct mybufs *postdata)
{
	int sofar = 0;
	struct mybufs *thisp;
	int r;
	for (thisp = postdata; thisp; thisp = thisp->next) {
		r = mg_write(conn, thisp->data, thisp->len);
		if (r <= 0) break;
	}
}

void
my_gmt_time_string(char *buf, int len, time_t *t)
{
	time_t x;
	if (!t) {
		x = time(0);
		t = &x;
	}
	struct tm *tm = gmtime(t);
	strftime(buf, len, "%a, %d %b %Y %H:%M:%S GMT", tm);
}

void
my_send_no_cache_header(struct mybufs **outp)
{
	append_postdata_format(outp, "Cache-Control: no-cache, no-store, "
		"must-revalidate, private, max-age=0\r\n"
		"Pragma: no-cache\r\n"
		"Expires: 0\r\n");
}

const char *
my_get_response_code_text(int status)
{
	switch(status) {
	case 100:	return "Continue";
	case 101:	return "Switching Protocols";
	case 102:	return "Processing";
	case 200:	return "OK";
	case 201:	return "Created";
	case 202:	return "Accepted";
	case 203:	return "Non-Authoritative Information";
	case 204:	return "No Content";
	case 205:	return "Reset Content";
	case 206:	return "Partial Content";
	case 300:	return "Multiple Choices";
	case 301:	return "Moved Permanently";
	case 302:	return "Found";
	case 303:	return "See Other";
	case 304:	return "Not Modified";
	case 400:	return "Bad Request";
	case 401:	return "Unauthorized";
	case 403:	return "Forbidden";
	case 404:	return "Not Found";
	case 405:	return "Method Not Allowed";
	case 410:	return "Gone";
	case 411:	return "Length Required";
	case 500:	return "Internal Server Error";
	case 501:	return "Not Implemented";
	default:	return "Unknown Problem or Internal Error";
	}
}

int
escape_html_characters2(char *buf, int len, const char *cp, int clen)
{
	int c, l;
	char cbuf[4];
	char *tp;
	int r;

	if (!len) return 0;
	r = 0;
	for (;clen;--clen) {
		c = *cp++;
		switch(c) {
		case '<': tp = "&lt;"; break;
		case '>': tp = "&gt;"; break;
		case '&': tp = "&amp;"; break;
		default:
			*cbuf = c;
			cbuf[1] = 0;
			tp = cbuf;
		}
		l = strlen(tp);
		if (l > (len-1)) {
			break;
		}
		++r;
		memcpy(buf, tp, l);
		buf += l;
		len -= l;
		if (len < 1) break;
	}
	--len;
	buf[len] = 0;
	return r;
}

int
escape_html_characters(char *buf, int len, const char *cp)
{
	return escape_html_characters2(buf, len, cp, strlen(cp));
}

int
printenv(struct mg_connection *conn,
	struct mg_request_info const *req_info,
	struct mybufs *postdata)
{
	struct mybufs *output = 0, *headers = 0;
	char timebuf[80];
	char tempbuf[1024];
	int status;
	struct sockaddr *lsa;

	lsa = mg_get_local_addr(conn);

	my_gmt_time_string(timebuf, sizeof timebuf, NULL);
	append_postdata_format(&output, "<!DOCTYPE html\r\n"
		"\tPUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\"\r\n"
		"\t\"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">\r\n");
	append_postdata_format(&output, "<html xmlns=\"http://www.w3.org/1999/xhtml\" lang=\"en-US\" xml:lang=\"en-US\">\r\n");
	append_postdata_format(&output, "<head>\r\n"
		"<title>%s</title>\r\n"
		"<meta http-equiv=\"Content-Type\" content=\"text/html; charset=iso-8859-1\" />\r\n"
		"</head>\r\n", "Untitled Document");
	append_postdata_format(&output, "<body>\r\n<pre>");
	switch (((struct sockaddr_in*)lsa)->sin_family) {
	case AF_INET:
		append_postdata_format(&output, "SERVER_PORT=%d\r\n",
			ntohs(((struct sockaddr_in*)lsa)->sin_port));
		break;
	}
	append_postdata_format(&output, "REQUEST_METHOD=%s\r\n",
		req_info->request_method);
	append_postdata_format(&output, "REMOTE_PORT=%d\r\n",
		req_info->remote_port);
	escape_html_characters(tempbuf, sizeof tempbuf, req_info->request_uri);
	append_postdata_format(&output, "REQUEST_URI=%s\r\n",
		tempbuf);
	escape_html_characters(tempbuf, sizeof tempbuf, req_info->local_uri);
	append_postdata_format(&output, "LOCAL_URI=%s\r\n",
		tempbuf);
	append_postdata_format(&output, "HTTPS=%s\r\n",
		req_info->is_ssl ? "on" : "off");
	if (req_info->query_string) {
		escape_html_characters(tempbuf, sizeof tempbuf, req_info->query_string);
		append_postdata_format(&output, "QUERY_STRING=%s\r\n",
			tempbuf);
	}
	append_postdata_format(&output, "</pre>\r\n");
	if (postdata) {
		int sofar = 0;
		struct mybufs *thisp;
		for (thisp = postdata; thisp; thisp = thisp->next) {
			int r, s;
			s = 0;
			while (s < thisp->len) {
				r = escape_html_characters2(tempbuf, sizeof tempbuf,
					thisp->data + s, thisp->len - s);
				if (!r) break;
				s += r;
				append_postdata_format(&output, "%s", tempbuf);
			}
			sofar += thisp->len;
		}
	}
	append_postdata_format(&output, "</body>\r\n");
	append_postdata_format(&output, "</html>\r\n");
	status = 200;
	append_postdata_format(&headers, "HTTP/1.1 %d %s\r\n",
		status,
		my_get_response_code_text(status));
	my_send_no_cache_header(&headers);
	append_postdata_format(&headers, "Date: %s\r\n", timebuf);
	append_postdata_format(&headers, "Content-Length: %d\r\n",
		compute_postdata_len(output));
	append_postdata_format(&headers, "Content-Type: %s\r\n",
		"text/html; charset=ISO-8859-1");
	append_postdata_format(&headers, "\r\n");
	copy_postdata_to_mg(conn, headers);
	copy_postdata_to_mg(conn, output);
	free_postdata(output);
	free_postdata(headers);
	free_postdata(postdata);
	return status;
}

int
my_begin_request(struct mg_connection *conn)
{
	struct mg_request_info const *req_info = mg_get_request_info(conn);
	struct myhttpd_data *me = (struct myhttpd_data*)(req_info->user_data);
	int i;
	char const *cl = 0;
	struct mybufs *postdata;

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
	postdata = 0;
	if (!strcmp(req_info->request_method, "POST")) {
		char *ep = 0;
		int c, totlen, sofar;
		totlen = cl ? strtol(cl, &ep, 0) : -1;
		if (cl)
			fprintf(stdout, "reading content: %d\n", totlen);
		for (sofar = 0;;sofar += c) {
			char buf[500];
			c = mg_read(conn, buf, sizeof buf);
			if (c <= 0) break;
			append_postdata(&postdata,  buf, c);
		}
	}
	if (postdata) {
		int sofar = 0;
		struct mybufs *thisp;
		for (thisp = postdata; thisp; thisp = thisp->next) {
			fprintf (stdout, "dt%d-%d: %.*s\n",
				sofar, sofar+thisp->len,
				thisp->len, thisp->data);
			sofar += thisp->len;
		}
	}
	if (!strcmp(req_info->uri, "/test-sp/printenv")) {
		return printenv(conn, req_info, postdata);
	}
	free_postdata(postdata);
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
	*cpp = 0;

	ctx = mg_start(cb, ud, (const char **) options);
	for (;;) {
		pause();
	}
	exit(rc);
}
