/* utilities to parse valid HTTP times
   and to generate RFC 822/1123 date 
   
   (C)Copyright 2014 Simon Urbanek

   License: BSD
*/


/* -- interface -- */

char *posix2http(double ts); /* Note: returned buffer is static */
double http2posix(const char *c);


/* -- implementation -- */

#include <time.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static const char *c_wkd[7] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
static const char *c_mon[12] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul",
				 "Aug", "Sep", "Oct", "Nov", "Dec" };

static char date_buf[64];

char *posix2http(double ts) {
    time_t t = (time_t) ts;
    struct tm *tm = gmtime(&t);
    if (!tm) return 0;
    snprintf(date_buf, sizeof(date_buf),
	     "%s, %02d %s %d %02d:%02d:%02d GMT",
	     c_wkd[tm->tm_wday], tm->tm_mday, c_mon[tm->tm_mon],
	     tm->tm_year + 1900, tm->tm_hour, tm->tm_min, tm->tm_sec);
    return date_buf;
}

static int lookup(const char *c, const char **where, int n) {
    int i;
    for (i = 0; i < n; i++)
	if (!memcmp(c, where[i], 3)) return i;
    return -1;
}

static double parse_hms(const char **c_ptr) {
    int h,m,s;
    const char *c = *c_ptr;
    while (*c == ' ') c++;
    h = atoi(c);
    while (*c >= '0' && *c <= '9') c++;
    if (*c != ':') return -1.0;
    c++;
    m = atoi(c);
    while (*c >= '0' && *c <= '9') c++;
    if (*c != ':') return -1.0;
    c++;
    s = atoi(c);
    while (*c >= '0' && *c <= '9') c++;
    *c_ptr = c;
    return (double) (s + (m * 60) + (h *3600));
}

double http2posix(const char *c) {
    int mon, day, year;
    double hms;
    struct tm tm;
    memset(&tm, 0, sizeof(tm));
    /* skip weekday */
    while (*c && *c != ' ') c++;
    if (!*c) return 0.0;
    while (*c == ' ') c++;
    /* this is now one of "01-Jan 2000", "01-Jan-00" or "Jan  1" */
    if (*c < '0' || *c > '9') { /* non-digit so it's either asctime() or invalid */
	if ((mon = lookup(c, c_mon, 12)) < 0)
	    return 0.0;
	while (*c && *c != ' ') c++;
	while (*c == ' ') c++;
	if (!*c)
	    return 0.0;
	day = atoi(c);
	while (*c && *c != ' ') c++;
	if (!*c)
	    return 0.0;
	if ((hms = parse_hms(&c)) < 0.0)
	    return 0.0;
	while (*c == ' ') c++;
	if (!*c)
	    return 0.0;
	year = atoi(c);
    } else { /* RFC 822/1123 or RFC 850/1036 - both can be parsed the same way
		if we ignore the the difference between ' ' and '-' and adjust year */
	day = atoi(c);
	while (*c >= '0' && *c <= '9') c++;
	while (*c == '-' || *c ==' ') c++;
	if ((mon = lookup(c, c_mon, 12)) < 0)
	    return 0.0;
	while (*c && (*c < '0' || *c > '9')) c++;
	if (!*c)
	    return 0.0;
	year = atoi(c);
	/* RFC 850/1036 doesn't say how to interpret two-digit years,
	   so we assume 70..99 are 1970..1999 and 00..69 are 2000..2069 */
	if (year < 70)
	    year += 2000;
	else if (year < 100)
	    year += 1900;
	while (*c && *c != ' ') c++;
	if (!*c || (hms = parse_hms(&c)) < 0.0)
	    return 0.0;
    }
    /* ok, we got hms and day/month/year - assemble it to POSIX */
    tm.tm_year = year - 1900;
    tm.tm_mday = day;
    tm.tm_mon = mon;
    return hms + (double) timegm(&tm);
}
