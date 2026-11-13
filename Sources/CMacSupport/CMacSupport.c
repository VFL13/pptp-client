#include "CMacSupport.h"
#include <errno.h>
#include <fcntl.h>
#include <readpassphrase.h>
#include <signal.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/socket.h>
#include <sys/sys_domain.h>
#include <unistd.h>

int pptp_open_utun(char *name, size_t capacity) {
    int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd < 0) return -1;
    struct ctl_info info = {0};
    strlcpy(info.ctl_name, "com.apple.net.utun_control", sizeof(info.ctl_name));
    if (ioctl(fd, CTLIOCGINFO, &info) < 0) goto failed;
    struct sockaddr_ctl address = {0};
    address.sc_len = sizeof(address);
    address.sc_family = AF_SYSTEM;
    address.ss_sysaddr = AF_SYS_CONTROL;
    address.sc_id = info.ctl_id;
    address.sc_unit = 0; /* Allocate a new interface; never reuse another VPN's. */
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) < 0) goto failed;
    socklen_t length = (socklen_t)capacity;
    if (getsockopt(fd, SYSPROTO_CONTROL, 2 /* UTUN_OPT_IFNAME */, name, &length) < 0) goto failed;
    if (capacity == 0 || memchr(name, 0, capacity) == NULL) { errno = EINVAL; goto failed; }
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) goto failed;
    return fd;
failed:;
    int saved = errno;
    close(fd);
    errno = saved;
    return -1;
}

int pptp_read_password(char *buffer, size_t capacity) {
    return readpassphrase("VPN password: ", buffer, capacity, RPP_ECHO_OFF | RPP_REQUIRE_TTY) ? 0 : -1;
}

static volatile sig_atomic_t cancelled = 0;
static struct sigaction previous[3];
static const int signals_to_handle[3] = {SIGINT, SIGTERM, SIGHUP};
static int installed = 0;
static void on_signal(int signal_number) { (void)signal_number; cancelled = 1; }

int pptp_install_signals(void) {
    struct sigaction action = {0};
    action.sa_handler = on_signal;
    sigemptyset(&action.sa_mask);
    cancelled = 0;
    for (int i = 0; i < 3; i++) {
        if (sigaction(signals_to_handle[i], &action, &previous[i]) < 0) {
            for (int j = 0; j < i; j++) sigaction(signals_to_handle[j], &previous[j], NULL);
            return -1;
        }
    }
    installed = 1;
    return 0;
}

void pptp_restore_signals(void) {
    if (!installed) return;
    for (int i = 0; i < 3; i++) sigaction(signals_to_handle[i], &previous[i], NULL);
    installed = 0;
}
int pptp_cancelled(void) { return cancelled != 0; }

void pptp_clear(void *buffer, size_t size) {
    volatile unsigned char *cursor = buffer;
    while (size--) *cursor++ = 0;
}
