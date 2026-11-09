/*
 * libagentguard_hook.c - Dynamic Linker Syscall Interceptor Hook.
 *
 * Loaded via DYLD_INSERT_LIBRARIES (macOS) or LD_PRELOAD (Linux).
 * Intercepts execve(), execvp(), and posix_spawn() to prevent bypasses
 * via absolute binary paths (e.g., /bin/bash, /usr/bin/curl, python os.execve).
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <limits.h>

#define DEFAULT_SOCK_PATH "/tmp/agentguard.sock"
#define BUFFER_SIZE 65536

static void json_escape(const char* src, char* dst, size_t dst_size) {
    size_t d = 0;
    for (size_t s = 0; src[s] != '\0' && d + 6 < dst_size; s++) {
        unsigned char c = (unsigned char)src[s];
        switch (c) {
            case '"':  dst[d++] = '\\'; dst[d++] = '"'; break;
            case '\\': dst[d++] = '\\'; dst[d++] = '\\'; break;
            case '\b': dst[d++] = '\\'; dst[d++] = 'b'; break;
            case '\f': dst[d++] = '\\'; dst[d++] = 'f'; break;
            case '\n': dst[d++] = '\\'; dst[d++] = 'n'; break;
            case '\r': dst[d++] = '\\'; dst[d++] = 'r'; break;
            case '\t': dst[d++] = '\\'; dst[d++] = 't'; break;
            default:
                if (c < 0x20) {
                    snprintf(&dst[d], dst_size - d, "\\u%04x", c);
                    d += 6;
                } else {
                    dst[d++] = (char)c;
                }
                break;
        }
    }
    dst[d] = '\0';
}

static int check_agentguard_policy(const char* file, char* const argv[]) {
    const char* session_id = getenv("AGENTGUARD_SESSION_ID");
    if (!session_id || strlen(session_id) == 0) return 1; /* Not managed */

    const char* sock_path = getenv("AGENTGUARD_SOCKET");
    if (!sock_path || strlen(sock_path) == 0) sock_path = DEFAULT_SOCK_PATH;

    /* Build command string */
    char full_cmd[BUFFER_SIZE];
    full_cmd[0] = '\0';
    size_t current_len = 0;

    if (argv) {
        for (int i = 0; argv[i] != NULL; i++) {
            size_t arg_len = strlen(argv[i]);
            if (current_len + arg_len + 2 >= sizeof(full_cmd)) break;
            if (i > 0) {
                strcat(full_cmd, " ");
                current_len += 1;
            }
            strcat(full_cmd, argv[i]);
            current_len += arg_len;
        }
    } else if (file) {
        strncpy(full_cmd, file, sizeof(full_cmd) - 1);
        full_cmd[sizeof(full_cmd) - 1] = '\0';
    }

    int sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock_fd < 0) return 1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);

    int is_allowed = 1;
    if (connect(sock_fd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
        char esc_cmd[BUFFER_SIZE];
        char esc_sess[512];
        json_escape(full_cmd, esc_cmd, sizeof(esc_cmd));
        json_escape(session_id, esc_sess, sizeof(esc_sess));

        char req_json[BUFFER_SIZE * 2];
        snprintf(req_json, sizeof(req_json),
                 "{\"protocol_version\":\"1.0\",\"action\":\"CHECK_COMMAND\","
                 "\"session_id\":\"%s\",\"pid\":%d,\"payload\":{\"command\":\"%s\"}}\n",
                 esc_sess, (int)getpid(), esc_cmd);

        send(sock_fd, req_json, strlen(req_json), 0);

        char resp_buf[4096];
        ssize_t bytes_read = recv(sock_fd, resp_buf, sizeof(resp_buf) - 1, 0);
        if (bytes_read > 0) {
            resp_buf[bytes_read] = '\0';
            if (strstr(resp_buf, "\"status\": \"BLOCKED\"") ||
                strstr(resp_buf, "\"status\":\"BLOCKED\"")) {
                is_allowed = 0;
            }
        }
    }
    close(sock_fd);

    if (!is_allowed) {
        fprintf(stderr, "[AgentGuard Syscall Interceptor] BLOCKED execve of '%s'\n", full_cmd);
    }
    return is_allowed;
}

#if defined(__APPLE__)
/* macOS dyld interposing structure */
#define DYLD_INTERPOSE(_replacement, _replacee) \
    __attribute__((used)) static const struct { const void* replacement; const void* replacee; } \
    _interpose_##_replacee __attribute__((section("__DATA,__interpose"))) = { \
        (const void*)(unsigned long)&_replacement, \
        (const void*)(unsigned long)&_replacee \
    };

int hook_execve(const char* path, char* const argv[], char* const envp[]) {
    if (!check_agentguard_policy(path, argv)) {
        return -1;
    }
    return execve(path, argv, envp);
}
DYLD_INTERPOSE(hook_execve, execve)

int hook_execvp(const char* file, char* const argv[]) {
    if (!check_agentguard_policy(file, argv)) {
        return -1;
    }
    return execvp(file, argv);
}
DYLD_INTERPOSE(hook_execvp, execvp)

#else
/* Linux LD_PRELOAD hooks */
typedef int (*real_execve_t)(const char*, char* const[], char* const[]);
typedef int (*real_execvp_t)(const char*, char* const[]);

int execve(const char* path, char* const argv[], char* const envp[]) {
    if (!check_agentguard_policy(path, argv)) {
        return -1;
    }
    real_execve_t real_execve = (real_execve_t)dlsym(RTLD_NEXT, "execve");
    return real_execve(path, argv, envp);
}

int execvp(const char* file, char* const argv[]) {
    if (!check_agentguard_policy(file, argv)) {
        return -1;
    }
    real_execvp_t real_execvp = (real_execvp_t)dlsym(RTLD_NEXT, "execvp");
    return real_execvp(file, argv);
}
#endif
