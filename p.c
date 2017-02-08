#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include "p.h"

void
free_postdata(struct toybufs *postdata)
{
	struct toybufs *next;
	for (; postdata; postdata = next) {
		next = postdata->next;
		free(postdata);
	}
}

void prefix_postdata(struct toybufs **postdata, char *buf, int len)
{
	struct toybufs *oldp = *postdata, *thisp;

	*postdata = 0;
	append_postdata(postdata, buf, len);

	for (thisp = oldp; thisp; thisp = thisp->next)
		append_postdata(postdata, thisp->data, thisp->len);
	free_postdata(oldp);
}

void
append_postdata(struct toybufs **postdata, char *buf, int len)
{
	struct toybufs *thisp, **nextp;
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
append_postdata_format(struct toybufs **postdata, char *fmt, ...)
{
	char buf[65536];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof buf, fmt, ap);
	va_end(ap);
	append_postdata(postdata, buf, strlen(buf));
}

void
prefix_postdata_format(struct toybufs **postdata, char *fmt, ...)
{
	char buf[65536];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof buf, fmt, ap);
	va_end(ap);
	prefix_postdata(postdata, buf, strlen(buf));
}

int
compute_postdata_len(struct toybufs *postdata)
{
	struct toybufs *thisp;
	int r;
	r = 0;
	for (thisp = postdata; thisp; thisp = thisp->next) {
		r += thisp->len;
	}
	return r;
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
