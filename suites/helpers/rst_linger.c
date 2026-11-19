/*
 * Test-only socket reset helper (never installed by jpm install).
 *
 * Arms SO_LINGER {1, 0} on a raw Janet TCP socket stream so closing it emits
 * an immediate TCP RST across POSIX and Windows stacks alike (BSDs/FreeBSD
 * emit FIN on close even when unread bytes sit in the receive buffer). Kept
 * strictly outside production jsec modules.
 */

#include <janet.h>

#ifdef JANET_WINDOWS
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#endif

static Janet cfun_arm_abortive_close(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    JanetStream *stream = janet_getabstract(argv, 0, &janet_stream_type);
    janet_stream_flags(stream, JANET_STREAM_SOCKET);
    struct linger lg;
    lg.l_onoff = 1;
    lg.l_linger = 0;
#ifdef JANET_WINDOWS
    if (setsockopt((SOCKET)stream->handle, SOL_SOCKET, SO_LINGER,
                   (const char *)&lg, (int)sizeof(lg)) != 0) {
        janet_panicf("setsockopt(SO_LINGER) failed: WSA error %d",
                     WSAGetLastError());
    }
#else
    if (setsockopt(stream->handle, SOL_SOCKET, SO_LINGER, &lg,
                   (socklen_t)sizeof(lg)) != 0) {
        janet_panicf("setsockopt(SO_LINGER) failed: %s", strerror(errno));
    }
#endif
    return argv[0];
}

static const JanetReg cfuns[] = {
    {"arm-abortive-close", cfun_arm_abortive_close,
     "(arm-abortive-close socket-stream)\n\n"
     "Arm SO_LINGER {1, 0} on a raw socket stream so closing it sends RST."},
    {NULL, NULL, NULL}};

JANET_MODULE_ENTRY(JanetTable *env) {
    janet_cfuns(env, "jsec-test-rst", cfuns);
}
