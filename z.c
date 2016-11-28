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

#include "z.h"

int j;

zxid_ses *zxid_mini_httpd_filter(zxid_conf * cf, 
	const char* method, const char* uri_path,
	const char* qs, const char* cookie_hdr)
{
	zxid_ses *ses = zxid_alloc_ses(cf);
	zxid_cgi cgi[1];
	int len, qs_len;
	int request_url_len;
	char *cp;
	char *request_url;

	memset(cgi, 0, sizeof *cgi);

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
	len = strlen(uri_path);
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
}
