// #include <pthread.h>
// #include <stdlib.h>
#include <unistd.h>
#include <errno.h>
// #include <stdio.h>
// #include <string.h>
// #include <stdarg.h>
// #include <sys/socket.h>
// #include <netinet/in.h>

#include <openssl/evp.h>

// did I mispell zx ?
// XXX yes I did; fixme zxid cmake
#include <zx/platform.h>
#include <zx/errmac.h>
#include <zx/zx.h>
#include <zx/zxid.h>
#include <zx/zxidpriv.h>
#include <zx/zxidconf.h>
#include <zx/zxidutil.h>
// #include <zx/c/zxidvers.h>
#define AUTO_FLAGS 0x6ea8

#include "civetweb.h"

#include "p.h"
#include "z.h"

int j;

int
zxid_mini_httpd_read_post(struct mybufs *postdata, char **outp)
{
	char *buf;
	char *cp;
	int len;

	cp = malloc(1 + (len = compute_postdata_len(postdata)));
	copy_postdata_to_buf(cp, len, postdata);
	cp[len] = 0;
	return len;
}

int
zxid_mini_httpd_process_zxid_simple_outcome(zxid_conf *cf,
	struct mg_connection *conn,
	zxid_ses *ses, const char *uri_path, const char *cookie_hdr,
	char *request_data)
{
	struct mybufs *output = 0, *headers = 0;
	int status;
	char *content_type = 0;
	char *p, *ep;
	int content_type_len, request_data_len;
	char timebuf[80];

	my_gmt_time_string(timebuf, sizeof timebuf, NULL);

	if (cookie_hdr && *cookie_hdr)
		append_postdata_format(&headers, "Set-Cookie: %s\r\n", cookie_hdr);
	switch(*request_data) {
	case 'L':
		status = 302;
		append_postdata_format(&output, "SAML Redirect\r\n");
		if (ses->setcookie) {
			append_postdata_format(&headers, "Set-Cookie: %s\r\n", ses->setcookie);
		}
		if (ses->setptmcookie) {
			append_postdata_format(&headers, "Set-Cookie: %s\r\n", ses->setptmcookie);
		}
		break;
	case 'C':
		fprintf(stderr,"request_data - case C: %s\n", request_data);
		content_type = request_data;
		request_data += 14;	/* "skip Content-Type:" */
		p = strchr(request_data, '\r');
		if (!p) goto E501;
		p += 2;
		content_type_len = p - content_type;
		p += 16;		/* "skip Content-Length:" */
fprintf(stderr,"About to strtol: %.8s\n", p);
		request_data_len = strtol(p, &ep, 10);
		request_data = strchr(p, '\r');
		if (!request_data)
			goto E501;
		request_data += 4;	/* skip \r\n\r\n */
		append_postdata(&output, request_data, request_data_len);
		status = 200;
		break;
	case 'z':
		fprintf(stderr,"request_data - case z: %s\n", request_data);
		goto E501;
	E501:
	default:
		content_type = 0;
		status = 501;
		append_postdata_format(&output, "Server Fault\r\n");
	}

	append_postdata_format(&headers, "HTTP/1.1 %d %s\r\n",
		status,
		my_get_response_code_text(status));
	append_postdata_format(&headers, "Date: %s\r\n", timebuf);
	append_postdata_format(&headers, "Content-Length: %d\r\n",
		compute_postdata_len(output));
	if (content_type) {
fprintf(stderr,"Custom content_type: %d<%.*s>\n",
content_type_len, content_type_len, content_type);
		append_postdata(&headers, content_type, content_type_len);
	} else {
		append_postdata_format(&headers, "Content-Type: %s\r\n",
			"text/plain");
	}
	append_postdata_format(&headers, "\r\n");
	copy_postdata_to_mg(conn, headers);
	copy_postdata_to_mg(conn, output);
	free_postdata(output);
	free_postdata(headers);
	return status;
}

int
zxid_mini_httpd_step_up(zxid_conf *cf,
	struct mg_connection *conn,
	zxid_cgi *cgi, zxid_ses *ses,
	const char *uri_path, const char *cookie_hdr)
{
	char *request_data;

	if (!ses)	// XXX can this happen?  should it be returned?
		ses = zxid_alloc_ses(cf);
	request_data = zxid_simple_no_ses_cf(cf, cgi, ses, 0, AUTO_FLAGS);
	return zxid_mini_httpd_process_zxid_simple_outcome(cf, conn,
		ses, uri_path, cookie_hdr,
		request_data);
}

int
zxid_mini_httpd_filter(zxid_conf * cf,
	struct mg_connection *conn,
	struct mybufs *postdata,
	zxid_ses**sessp)
{
	struct mg_request_info const *req_info = mg_get_request_info(conn);
	zxid_ses *ses = zxid_alloc_ses(cf);
	zxid_cgi cgi[1];
	int len, qs_len, uri_len;
	int request_url_len;
	char *cp;
	char *request_url;
	const char *method = req_info->request_method;
	const char *uri_path = req_info->request_uri;	// or local_url?
	const char *qs = req_info->query_string;
	char *request_data = 0;
	int request_data_len = -1;
	int r;
	const char *cookie_hdr = 0;
	int i;

	*sessp = ses;
	memset(cgi, 0, sizeof *cgi);
	for (i = 0; i < req_info->num_headers; ++i) {
		if (!strncasecmp("cookie",
				req_info->http_headers[i].name, 6))
			cookie_hdr = req_info->http_headers[i].value;
	}

	// zxid_mini_httpd_check_redirect_hack
	cgi->uri_path = (char *) uri_path;
	if (!cf->redirect_hack_zxid_qs || !*cf->redirect_hack_zxid_qs)
		;
	else if (!*qs)
		cgi->qs = cf->redirect_hack_zxid_qs;
	else {
		qs_len = strlen(qs);
		len = strlen(cf->redirect_hack_zxid_qs);
		cp = ZX_ALLOC(cf->ctx, len + qs_len + 2);
		memcpy(cp, cf->redirect_hack_zxid_qs, len);
		cp[len] = '&';
		memcpy(cp + len + 1, qs, qs_len + 1);
		cgi->qs = cp;
	}
	// XXX check, is qs a leak?
	if (cgi->qs && *cgi->qs) {
		cp = zx_dup_cstr(cf->ctx, cgi->qs);
		zxid_parse_cgi(cf, cgi, cp);
	}
	if (cf->ses_cookie_name && *cf->ses_cookie_name && cookie_hdr) {
		zxid_get_sid_from_cookie(cf, cgi, cookie_hdr);
	}
	// zxid_mini_httpd_check_protocol_url
	for (cp = cf->burl; *cp && *cp != ':' && *cp != '/'; ++cp)
		;
	if (*cp == ':' && cp[1] == '/' && cp[2] == '/') {
		for (cp += 3; *cp && *cp != '/'; ++cp)
			;
	}
	request_url = cp;
	len = strlen(cp);
	for (cp = request_url + len-1; cp > request_url; --cp)
		if (*cp == '?') break;
	if (cp == request_url)
		cp = request_url + request_url_len;
	request_url_len = cp - request_url;
	uri_len = strlen(uri_path);
	if (uri_len == request_url_len && !memcmp(request_url, uri_path, uri_len)) {
		if (*method == 'P') {
			request_data_len = zxid_mini_httpd_read_post(postdata,
				&request_data);
			if (cgi->op == 'S') {
				r = zxid_sp_soap_parse(cf, cgi, ses,
					request_data_len, request_data);
			} else {
				zxid_parse_cgi(cf, cgi, request_data);
			}
		}
		switch(cgi->op) {
		case 'L':
		case 'A':
			break;
		default:
			if (!cgi->sid || !zxid_get_ses(cf, ses, cgi->sid))
				break;
			request_data = zxid_simple_ses_active_cf(cf, cgi,
				ses, 0, AUTO_FLAGS);
			if (request_data) {
				return
zxid_mini_httpd_process_zxid_simple_outcome(cf, conn,
					ses, uri_path, cookie_hdr,
					request_data);
			}
		}
		return zxid_mini_httpd_step_up(cf, conn, cgi, ses, uri_path,
			cookie_hdr);
	}
	// note: zxid_is_wsp == do zxid_mini_httpd_wsp_response
fprintf (stderr,"ha! got here!\n");
	if (zx_match(cf->wsp_pat, uri_path)) {
	}
	// zxid_mini_httpd_wsp
	// zxid_mini_httpd_uma
	// zxid_mini_httpd_sso
	if (zx_match(cf->sso_pat, uri_path)) {
		if (!qs || *qs != 'l') {
			cgi->op = 'E';
		}
		if (cgi->sid && cgi->sid[0] && zxid_get_ses(cf, ses, cgi->sid)) {
			request_data = zxid_simple_ses_active_cf(cf, cgi,
				ses, 0, AUTO_FLAGS);
			if (request_data) {
				return
zxid_mini_httpd_process_zxid_simple_outcome(cf, conn,
					ses, uri_path, cookie_hdr,
					request_data);
			}
		}
		return zxid_mini_httpd_step_up(cf, conn, cgi, ses, uri_path,
			cookie_hdr);
	} else {
fprintf (stderr,"sso_path=<%s> uri_path=<%s>: no match\n", cf->sso_pat, uri_path);
		return 0;
	}
}
