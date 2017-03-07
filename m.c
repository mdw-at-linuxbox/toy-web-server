#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "civetweb.h"

#include <curl/curl.h>

/* ughugh. zxid.h needs these next 3 to make zxid_conf proper size... */
#define USE_CURL 1
#define USE_PTHREAD 1
#define USE_OPENSSL 1
#include "p.h"
#include "m.h"
#include "s.h"
#include <openssl/evp.h>
#include "zx/zxid.h"
#include "z.h"

struct m_work {
	struct s_store gstore[1], lstore[1];
	struct s_store *store;
};

struct toyhttpd_data {
	int foo;
};

struct toyconn_data {
	zxid_ses *ses;
	zxid_conf cf[1];
	int foo[128];	/* paranoia */
};

struct toy_request {
	struct mg_connection *conn;
	struct mg_request_info const *req_info;
	struct toyconn_data *cdata;
	struct toybufs *postdata;
};

char *zxid_confstr = "PATH=/tmp/zxid/&SSO_PAT=/test-sp/**&DEBUG=1";
char *portstr = "7443s";
char *certstr = "sign-nopw-cert.pem";
int sflag;
int vflag = 1;
int Dflag;

int rc;
pthread_key_t local_store;

void
copy_postdata_to_mg(struct mg_connection *conn, struct toybufs *postdata)
{
	int sofar = 0;
	struct toybufs *thisp;
	int r;
	for (thisp = postdata; thisp; thisp = thisp->next) {
		r = mg_write(conn, thisp->data, thisp->len);
		if (r <= 0) break;
		if (r != thisp->len) {
fprintf(stderr,"Only wrote %d of %d bytes!!!\n", r, thisp->len);
		}
	}
}

void copy_postdata_to_buf(char *buf, int buflen, struct toybufs *postdata)
{
	int sofar = 0;
	struct toybufs *thisp;
	int r;
	int l;
	for (thisp = postdata; thisp; thisp = thisp->next) {
		if (!buflen) break;
		l = buflen;
		if (l > thisp->len) l = thisp->len;
		memcpy(buf, thisp->data, l);
		buf += l;
		buflen -= l;
	}
}

void
my_send_no_cache_header(struct toybufs **outp)
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
	if (!len) --buf;
	*buf = 0;
	return r;
}

int
escape_html_characters(char *buf, int len, const char *cp)
{
	return escape_html_characters2(buf, len, cp, strlen(cp));
}

int
printenv(struct toy_request *myrequest)
{
	struct toybufs *output = 0, *headers = 0;
	char timebuf[80];
	char tempbuf[1024];
	int status;
	struct sockaddr *lsa;
#define TOY_MAX_ENV 256
	char *envp[TOY_MAX_ENV];

	*envp = 0;
	lsa = mg_get_local_addr(myrequest->conn);

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
		myrequest->req_info->request_method);
	append_postdata_format(&output, "REMOTE_PORT=%d\r\n",
		myrequest->req_info->remote_port);
	escape_html_characters(tempbuf, sizeof tempbuf, myrequest->req_info->request_uri);
	append_postdata_format(&output, "REQUEST_URI=%s\r\n",
		tempbuf);
	escape_html_characters(tempbuf, sizeof tempbuf, myrequest->req_info->local_uri);
	append_postdata_format(&output, "LOCAL_URI=%s\r\n",
		tempbuf);
	append_postdata_format(&output, "HTTPS=%s\r\n",
		myrequest->req_info->is_ssl ? "on" : "off");
	if (myrequest->req_info->query_string) {
		escape_html_characters(tempbuf, sizeof tempbuf, myrequest->req_info->query_string);
		append_postdata_format(&output, "QUERY_STRING=%s\r\n",
			tempbuf);
	}
	if (myrequest->cdata->ses) {
		int i, r;
		char *remoteuser = 0;
		r = zxid_pool2env(myrequest->cdata->cf, myrequest->cdata->ses,
			envp, TOY_MAX_ENV-1, &remoteuser);
		envp[r] = 0;
		if (remoteuser) {
			escape_html_characters(tempbuf, sizeof tempbuf, remoteuser);
			append_postdata_format(&output, "REMOTE_USER=%s\r\n",
				tempbuf);
		}
		for (i = 0; envp[i]; ++i) {
			escape_html_characters(tempbuf, sizeof tempbuf, envp[i]);
			append_postdata_format(&output, "%s\r\n", tempbuf);
		}
	}
	append_postdata_format(&output, "</pre>\r\n");
	if (myrequest->postdata) {
		int sofar = 0;
		struct toybufs *thisp;
		for (thisp = myrequest->postdata; thisp; thisp = thisp->next) {
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
	copy_postdata_to_mg(myrequest->conn, headers);
	copy_postdata_to_mg(myrequest->conn, output);
	free_postdata(output);
	free_postdata(headers);
	free_postdata(myrequest->postdata);
	return status;
}

void
read_postdata(struct toybufs **outp, struct mg_connection *conn)
{
	struct mg_request_info const *req_info = mg_get_request_info(conn);
	int i;
	char const *cl = 0;
	for (i = 0; i < req_info->num_headers; ++i) {
		if (!strncasecmp("content-length",
				req_info->http_headers[i].name, 14))
			cl = req_info->http_headers[i].value;
	}
	char *ep = 0;
	int c, totlen, sofar;
	totlen = cl ? strtol(cl, &ep, 0) : -1;
	if (vflag && cl)
		fprintf(stdout, "reading content: %d\n", totlen);
	for (sofar = 0;;sofar += c) {
		char buf[500];
		c = mg_read(conn, buf, sizeof buf);
		if (c <= 0) break;
		append_postdata(outp,  buf, c);
	}
}

void * my_memory_reallocator(void *p, size_t n)
{
	char *r;
	int oldn;
	void *data;
	struct m_work *work = 0;

	data = pthread_getspecific(local_store);
	if (data) {
		work = (struct m_work *) data;
	}

	if (p) {
		r = p;
		r -= 16;
		oldn = *((int *)r);
	}
	n += 16;
	char *new = my_s_alloc(work->store, n);
	if (!new) {
		return 0;
	}
	*((int *)new) = n;
	if (p) {
		if (n > oldn) n = oldn;
		memcpy(new+16, r+16, n - 16);
	}
	return new+16;
}

void * my_memory_allocator(size_t n)
{
	return my_memory_reallocator(0, n);
}

void my_memory_free(void *p)
{
}

int
my_begin_request(struct mg_connection *conn)
{
	struct toyhttpd_data *me;
	int i;
	void *p;
	void *data;
	struct m_work *work = 0;
	int r = 0;
	struct toy_request myrequest[1];

	memset(myrequest, 0, sizeof *myrequest);
	myrequest->conn = conn;
	myrequest->req_info = mg_get_request_info(conn);
	me = (struct toyhttpd_data*)(myrequest->req_info->user_data);
	data = pthread_getspecific(local_store);
	if (data) {
		work = (struct m_work *) data;
	} else {
		work = malloc(sizeof *work);
		memset(work, 0, sizeof *work);
		work->store = work->gstore;
		if (!!pthread_setspecific(local_store, work)) {
			perror("my_begin_request");
			goto Done;	// 0 ???
		}
	}
	p = mg_get_user_connection_data(conn);
	if (p) {
		myrequest->cdata = (struct toyconn_data *) p;
	} else {
		myrequest->cdata = malloc(sizeof *myrequest->cdata);
if (Dflag) fprintf(stderr,"allocate myrequest->cdata: %d => %#lx\n", (int)(sizeof *myrequest->cdata), myrequest->cdata);
		memset(myrequest->cdata, 0, sizeof *myrequest->cdata);
		memset(myrequest->cdata->foo, 0xaa, sizeof myrequest->cdata->foo);
		mg_set_user_connection_data(conn, myrequest->cdata);
	}
if (Dflag) fprintf(stderr,"begin-request #0: %#lx [%x]\n", myrequest->cdata, myrequest->cdata->foo[0]);

	if (!myrequest->cdata->cf->ctx) {
		/* zxid_new_conf_to_cf - can't use, want
			custom memory allocator.
		*/
		myrequest->cdata->cf->ctx = zx_init_ctx();
		if (sflag) {
			myrequest->cdata->cf->ctx->malloc_func = my_memory_allocator;
			myrequest->cdata->cf->ctx->realloc_func = my_memory_reallocator;
			myrequest->cdata->cf->ctx->free_func = my_memory_free;
		}
if (Dflag) fprintf(stderr,"begin-request #92: %#lx [%x]\n", myrequest->cdata, myrequest->cdata->foo[0]);
		zxid_conf_to_cf_len(myrequest->cdata->cf, -1, zxid_confstr);
//NO!		myrequest->cdata->cf = zxid_new_conf_to_cf(zxid_confstr);
	}
if (Dflag) fprintf(stderr,"begin-request #1: %#lx [%x]\n", myrequest->cdata, myrequest->cdata->foo[0]);

	if (vflag) {
		fprintf (stdout, "method: %s\n", myrequest->req_info->request_method);
		fprintf (stdout, "uri: %s\n", myrequest->req_info->uri);
		if (myrequest->req_info->query_string)
			fprintf (stdout, "qs: %s\n", myrequest->req_info->query_string);
		fprintf (stdout, "user: %s\n", myrequest->req_info->remote_user);
		for (i = 0; i < myrequest->req_info->num_headers; ++i) {
			fprintf (stdout, "hd%d: %s=%s\n", i,
				myrequest->req_info->http_headers[i].name,
				myrequest->req_info->http_headers[i].value);
		}
	}
	if (!strcmp(myrequest->req_info->request_method, "POST")) {
		read_postdata(&myrequest->postdata, conn);
		if (myrequest->postdata) {
			int sofar = 0;
			struct toybufs *thisp;
			for (thisp = myrequest->postdata; thisp; thisp = thisp->next) {
				fprintf (stdout, "dt%d-%d: %.*s\n",
					sofar, sofar+thisp->len,
					thisp->len, thisp->data);
				sofar += thisp->len;
			}
		}
	}
if (Dflag) fprintf(stderr,"begin-request #2: %#lx [%x]\n", myrequest->cdata, myrequest->cdata->foo[0]);
	r = zxid_mini_httpd_filter(myrequest->cdata->cf, conn, myrequest->postdata, &myrequest->cdata->ses);
	if (r)
		goto Done;
	if (!memcmp(myrequest->req_info->uri, "/test-sp/printenv", 17)) {
		switch (myrequest->req_info->uri[17]) {
		case '/': case 0:
if (Dflag) fprintf(stderr,"begin-request #3: %#lx [%x]\n", myrequest->cdata, myrequest->cdata->foo[0]);
			r = printenv(myrequest);
			goto Done;
		default:
			break;
		}
	}
	if (!memcmp(myrequest->req_info->uri, "/test/printenv", 14)) {
		switch (myrequest->req_info->uri[14]) {
		case '/': case 0:
if (Dflag) fprintf(stderr,"begin-request #4: %#lx [%x]\n", myrequest->cdata, myrequest->cdata->foo[0]);
			r = printenv(myrequest);
			goto Done;
		default:
			break;
		}
	}
Done:
	free_postdata(myrequest->postdata);
if (Dflag) fprintf(stderr,"begin-request #5: %#lx [%x]\n", myrequest->cdata, myrequest->cdata->foo[0]);
	return r;
}

void
discard_connection_cdata(const struct mg_connection *conn)
{
	void *p;
	struct toyconn_data *cdata;
	struct zx_ctx *ctx;
	p = mg_get_user_connection_data(conn);
	mg_set_user_connection_data(conn, NULL);
	cdata = (struct toyconn_data *) p;
	if (!cdata) return;
	curl_easy_cleanup(cdata->cf->curl);
	cdata->cf->curl = 0;
	cdata->cf->cpath = 0;	/* parsed substring, not strdup */
				/* note that cpath gets alloc'd,
				 * then clobbered, leak there!
				 */
	if (cdata) {
		ctx = cdata->cf->ctx;
		zxid_free_conf(cdata->cf);
if (Dflag) fprintf(stderr,"free cdata: %#lx [%x]\n", cdata, cdata->foo[0]);
		memset(cdata, 0xaa, sizeof *cdata);
		free(cdata);
		if (ctx)
			zx_free_ctx(ctx);
	}
}

void
my_end_request(const struct mg_connection *conn, int reply_status_code)
{
	void *data;
	struct m_work *work = 0;

	// eventually, don't do this.
	discard_connection_cdata(conn);
	// but need much smarter storage allocation help
	// in zxid first.

	// delete everything that zxid asked for (this thread)
	data = pthread_getspecific(local_store);
	if (data) {
		work = (struct m_work *) data;
		my_s_release(work->store);
	}
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

void
my_close_connection(const struct mg_connection *conn)
{
	/* eventually, should only drop connection here. */
	discard_connection_cdata(conn);
}

struct mg_callbacks cb[1] = {{
	begin_request: my_begin_request,
	log_message: my_log_message,
	log_access: my_log_access,
	connection_close: my_close_connection,
	end_request: my_end_request,
}};

static void local_destroy(void *data)
{
	struct m_work *work = (struct m_work *)data;
	if (data) {
		my_s_release(work->gstore);
		my_s_release(work->lstore);
		free(data);
	}
	pthread_setspecific(local_store, NULL);
}

int process()
{
	struct mg_context *ctx;
	struct toyhttpd_data ud[1];
	char *options[40], **cpp;

	cpp = options;
	*cpp++ = "decode_url", *cpp++ = "no";
	*cpp++ = "enable_keep_alive", *cpp++ = "yes";
	*cpp++ = "validate_http_method", *cpp++ = "no";
	*cpp++ = "canonicalize_url_path", *cpp++ = "no";
	*cpp++ = "listening_ports", *cpp++ = portstr;
	if (certstr) {
		*cpp++ = "ssl_certificate", *cpp++ = certstr;
	}
	*cpp = 0;

	if (!!pthread_key_create(&local_store, local_destroy)) {
		perror("pthread_key_create");
		return 1;
	}
	curl_global_init(CURL_GLOBAL_ALL);

	ctx = mg_start(cb, ud, (const char **) options);
	for (;;) {
		pause();
	}
	return rc;
}

char usage[] = "Usage: myhttpd [-sDvq] [-z confstr] [-p N,Ns] [-c cert_key.pem]\n";

int
main(int ac, char **av)
{
	char *ap;
	char *cp;

	while (--ac) if(*(ap = *++av) == '-')
	while (*++ap) switch(*ap)
	{
	case 'D':
		++Dflag;
		break;
	case 's':
		++sflag;
		break;
	case 'q':
		vflag = 0;
		break;
	case 'v':
		++vflag;
		break;
	case 'c':
		if (ac < 1) {
			fprintf(stderr,"myhttpd: -c: missing option\n");
			goto Usage;
		}
		--ac;
		cp = *++av;
		certstr = strcmp(cp, "") ? cp : NULL;
		break;
	case 'p':
		if (ac < 1) {
			fprintf(stderr,"myhttpd: -p: missing option\n");
			goto Usage;
		}
		--ac;
		portstr = *++av;
		break;
	case 'z':
		if (ac < 1) {
			fprintf(stderr,"myhttpd: -z: missing option\n");
			goto Usage;
		}
		--ac;
		zxid_confstr = *++av;
	case '-':
		break;
	default:
		fprintf(stderr,"myhttpd: Bad option: %c\n", *ap);
	Usage:
		fprintf(stderr,"%s", usage);
		exit(1);
	} else {
		fprintf(stderr, "myhttpd: Unknown extra argument: %s\n", ap);
		goto Usage;
	}
	exit(process());
}
