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
#include "m.h"
#include "z.h"

int j;

int
pretty_print_expand(char *cp, int len, char *buf, int buflen)
{
	int l, r;
	char *p;
	char lp[30];
	r = len;
	for (p = cp; --len >= 0; ++p) {
		if (buflen < 1) ;
		else if (*p >= 040 && *p < 0177) --buflen, *buf++ = *p;
		else {
			sprintf (lp, "\\%03o", (unsigned char) *p);
			l = strlen(lp); if (l > (buflen-1)) l=(buflen-1);
			memcpy(buf, lp, l);
			buflen -= l; buf += l;
		}
	}
	if (buflen) *buf++ = 0;
	return r;
}

int
zxid_mini_httpd_read_post(zxid_conf * cf, struct toybufs *postdata, char **outp)
{
	char *cp;
	int len;

	cp = zx_alloc(cf->ctx, 1 + (len = compute_postdata_len(postdata)));
	copy_postdata_to_buf(cp, len, postdata);
	cp[len] = 0;
	*outp = cp;
	return len;
}

int
zxid_mini_httpd_process_zxid_simple_outcome(zxid_conf *cf,
	struct mg_connection *conn,
	zxid_ses *ses, const char *uri_path, const char *cookie_hdr,
	char *request_data)
{
	struct toybufs *output = 0, *headers = 0;
	int status;
	char *content_type = 0;
	char *p, *ep;
	int content_type_len, request_data_len;
	char timebuf[80];

	my_gmt_time_string(timebuf, sizeof timebuf, NULL);
	if (cookie_hdr && *cookie_hdr) {
		if (Dflag) fprintf(stderr,"zmhpzso: cookie_hdr: %s\n", cookie_hdr);
		append_postdata_format(&headers, "Set-Cookie: %s\r\n", cookie_hdr);
	}
	switch(*request_data) {
	case 'L':
		status = 302;
		append_postdata_format(&output, "SAML Redirect\r\n");
		request_data_len = strlen(request_data);
		for (p = request_data, ep = p + request_data_len; p < ep; ++p) {
			p = memchr(p, '\r', ep-p);
			if (!p) break;
			if (ep-p < 2) break;
			if (memcmp(p, "\r\n", 2))
				continue;
			p += 2;
			if (ep-p < 2) break;
			if (!memcmp(p, "\r\n", 2)) {
				request_data_len = p - request_data;
				p += 2;
				if (ep > p) {
char ltemp[256];
pretty_print_expand(p, ep-p, ltemp, sizeof ltemp);
fprintf(stderr,"Discarding case L unexpected data: <%s>\n", ltemp);
				}
				break;
			}
		}
#if 0
		p = strchr(request_data, '\r');
		if (p) {
			request_data_len = p-request_data;
{ char *ltemp = 0;
char *savedp, *p1 = 0; int r;
savedp = p;
while (*++p) switch(*p) {
case '\r':
case '\n':
break;
default:
if (!p1) p1 = p;
}
if (p1) {
ltemp = malloc(8192);
r = pretty_print_expand(p1, p-p1, ltemp, 8192);
fprintf(stderr,"zmhpzso: Huh?  L: %d<%s>\n", r, ltemp);
}
fprintf(stderr,"zmhpzso: zero %lx/%d\n", savedp, p-savedp);
memset(savedp, 'X', p-savedp);
}
		} else
			request_data_len = strlen(request_data);
#endif
// if (Dflag) {
// char ltemp[8192];
// pretty_print_expand(request_data, request_data_len, ltemp, sizeof ltemp);
// fprintf(stderr,"zmhpzso: Case L - <%s>\n", ltemp);
// }
		append_postdata(&headers, request_data, request_data_len);
		break;
	case 'C':
		fprintf(stderr,"zmhpzso: request_data - case C: %s\n", request_data);
		content_type = request_data;
		request_data += 14;	/* "skip Content-Type:" */
		p = strchr(request_data, '\r');
		if (!p) goto E501;
		p += 2;
		content_type_len = p - content_type;
		p += 16;		/* "skip Content-Length:" */
if (Dflag) fprintf(stderr,"zmhpzso: About to strtol: %.8s\n", p);
		request_data_len = strtol(p, &ep, 10);
		request_data = strchr(p, '\r');
		if (!request_data)
			goto E501;
		request_data += 4;	/* skip \r\n\r\n */
		append_postdata(&output, request_data, request_data_len);
		status = 200;
		break;
	case 'z':
if (Dflag) fprintf(stderr,"zmhpzso: request_data - case z: %s\n", request_data);
		goto E501;
	case 0:	/* Logged in case */
		// pool2apache(cf, r, ses.at);
		status = 0;
		return status;
	default:
if (Dflag) fprintf(stderr,"zmhpzso: request_data - ?unknown?: %s\n", request_data);
	E501:
		content_type = 0;
		status = 501;
		append_postdata_format(&output, "Server Fault\r\n");
	}

	prefix_postdata_format(&headers, "HTTP/1.1 %d %s\r\n",
		status,
		my_get_response_code_text(status));
	if (ses->setcookie) {
		append_postdata_format(&headers, "Set-Cookie: %s\r\n", ses->setcookie);
	}
	if (ses->setptmcookie) {
		append_postdata_format(&headers, "Set-Cookie: %s\r\n", ses->setptmcookie);
	}
	append_postdata_format(&headers, "Date: %s\r\n", timebuf);
	append_postdata_format(&headers, "Content-Length: %d\r\n",
		compute_postdata_len(output));
	if (content_type) {
if (Dflag) fprintf(stderr,"zmhpzso: Custom content_type: %d<%.*s>\n",
content_type_len, content_type_len, content_type);
		append_postdata(&headers, content_type, content_type_len);
	} else {
		append_postdata_format(&headers, "Content-Type: %s\r\n",
			"text/plain");
	}
	append_postdata_format(&headers, "\r\n");
	copy_postdata_to_mg(conn, headers);
#if 0
if (Dflag) {
int len = compute_postdata_len(headers);
char *buf = malloc(1 + len);
char *buf2 = malloc((len+5)*20);
copy_postdata_to_buf(buf, len, headers);
buf[len] = 0;
pretty_print_expand(buf, len, buf2, (len+5)*20);
fprintf(stderr,"Output headers: %d<%s>\n", len, buf2);
free(buf);
free(buf2);
}
#endif
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
if (Dflag) fprintf (stderr,"zmhsu: simple_outcome\n");
	return zxid_mini_httpd_process_zxid_simple_outcome(cf, conn,
		ses, uri_path, cookie_hdr,
		request_data);
}

int
zxid_mini_httpd_filter(zxid_conf * cf,
	struct mg_connection *conn,
	struct toybufs *postdata,
	zxid_ses**sessp)
{
	struct mg_request_info const *req_info = mg_get_request_info(conn);
	zxid_ses *ses = zxid_alloc_ses(cf);
	zxid_cgi cgi[1];
	int len, qs_len, uri_len;
	int burl_url_len;
	char *cp;
	char *burl_url;
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
		cgi->qs = (char *) qs;
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
		// XXX check, is qs a leak?
	}
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
	burl_url = cp;
	burl_url_len = strlen(cp);
	for (cp = burl_url + burl_url_len-1; cp > burl_url; --cp)
		if (*cp == '?') break;
	if (cp == burl_url)
		cp = burl_url + burl_url_len;
	burl_url_len = cp - burl_url;
	uri_len = strlen(uri_path);
	if (uri_len == burl_url_len && !memcmp(burl_url, uri_path, uri_len)) {
if (Dflag) fprintf (stderr,"zmhf: matching zxid pseudo node\n");
		if (*method == 'P') {
			request_data_len = zxid_mini_httpd_read_post(cf, postdata,
				&request_data);
			if (cgi->op == 'S') {
				r = zxid_sp_soap_parse(cf, cgi, ses,
					request_data_len, request_data);
			} else {
				zxid_parse_cgi(cf, cgi, request_data);
			}
		}
		switch(cgi->op) {
		default:
			if (!cgi->sid || !zxid_get_ses(cf, ses, cgi->sid))
				break;
			request_data = zxid_simple_ses_active_cf(cf, cgi,
				ses, 0, AUTO_FLAGS);
			if (!request_data)
				break;
if (Dflag) fprintf (stderr,"zmhf: case #1 simple_outcome\n");
			return
zxid_mini_httpd_process_zxid_simple_outcome(cf, conn,
				ses, uri_path, cookie_hdr,
				request_data);
		case 'L':
		case 'A':
			break;
		}
		return zxid_mini_httpd_step_up(cf, conn, cgi, ses, uri_path,
			cookie_hdr);
	}
if (Dflag) fprintf (stderr,"zmhpzso: (req %s no match for pseudo %s)\n", uri_path, burl_url);
	// note: zxid_is_wsp == do zxid_mini_httpd_wsp_response
if (Dflag) fprintf (stderr,"zmhpzso: ha! got here!\n");
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
if (Dflag) fprintf (stderr,"zmhf: case #2 simple_outcome\n");
				return
zxid_mini_httpd_process_zxid_simple_outcome(cf, conn,
					ses, uri_path, cookie_hdr,
					request_data);
			}
		}
		return zxid_mini_httpd_step_up(cf, conn, cgi, ses, uri_path,
			cookie_hdr);
	} else {
if (Dflag) fprintf (stderr,"zmhf: sso_path=<%s> uri_path=<%s>: no match\n", cf->sso_pat, uri_path);
		return 0;
	}
}

int zxid_pool2env(zxid_conf *cf, zxid_ses *ses, char **envp, int maxn, char **remoteuserp)
{
	struct zxid_map *map;
	struct zxid_attr *at, *av;
	char *name, *val;
	int envn = 0;

	for (at = ses->at; at; at = at->n) {
		name = at->name;
		val = at->val;
		if (!strcmp(name, "idpnid") && val && strcmp(val, "-"))
			*remoteuserp = val;
		map = zxid_find_map(cf->outmap, at->name);
		if (map) {
			if (map->rule == ZXID_MAP_RULE_DEL) {
				continue;
			}
			at->map_val = zxid_map_val(cf, 0, 0, map, at->name, at->val);
			if (map->dst && *map->dst && map->src && map->src[0] != '*') {
				name = map->dst;
			}
			val = at->map_val->s;
		}
		if (envn >= maxn) {
		TooMany:
fprintf(stderr,"zp2e: too many envs(max=%d)\n", maxn);
			goto Done;
		}
		envp[envn++] = zx_alloc_sprintf(cf->ctx, 0, "%s%s=%s",
			cf->mod_saml_attr_prefix, name, val);
		for (av = at->nv; av; av = av->n) {	/* multivalued */
			av->map_val = zxid_map_val(cf, 0, 0, map, at->name, av->val);
			if (envn >= maxn) goto TooMany;
			envp[envn++] = zx_alloc_sprintf(cf->ctx, 0, "%s%s=%s",
				cf->mod_saml_attr_prefix, name,
				map ? av->map_val->s : av->val);
		}
	}
Done:
	return envn;
}
