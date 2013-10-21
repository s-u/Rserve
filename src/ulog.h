#ifndef ULOG_H__
#define ULOG_H__

void ulog_set_path(const char *path);
void ulog_begin();
void ulog_add(const char *format, ...);
void ulog_end();
void ulog(const char *format, ...);
int ulog_enabled();

#endif
