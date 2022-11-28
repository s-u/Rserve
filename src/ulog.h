#ifndef ULOG_H__
#define ULOG_H__

void ulog_set_path(const char *path);
void ulog_set_app_name(const char *name);
void ulog_begin(void);
void ulog_add(const char *format, ...);
void ulog_end(void);
void ulog(const char *format, ...);
int ulog_enabled(void);
void ulog_reset(void);

#endif
