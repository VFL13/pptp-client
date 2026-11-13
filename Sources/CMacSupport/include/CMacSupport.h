#ifndef PPTP_MAC_SUPPORT_H
#define PPTP_MAC_SUPPORT_H
#include <stddef.h>
int pptp_open_utun(char *name, size_t capacity);
int pptp_read_password(char *buffer, size_t capacity);
int pptp_install_signals(void);
void pptp_restore_signals(void);
int pptp_cancelled(void);
void pptp_clear(void *buffer, size_t size);
#endif
