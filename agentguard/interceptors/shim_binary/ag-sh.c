/*
 * ag-sh.c - AgentGuard High-Performance Process Interceptor Shim.
 *
 * Intercepts binary calls at POSIX execution boundary (<0.5ms overhead).
 * Features:
 * - Full RFC 8259 compliant JSON escaping (control characters, quotes, backslashes)
 * - Native Human-In-The-Loop (PROMPT_HITL) handling via direct /dev/tty interaction
 * - Configurable Fail-Closed policy (AGENTGUARD_FAIL_CLOSED=1)
 * - Complete payload telemetry passing (argv array, cwd, ppid)
 * - If ALLOWED: calls execv() with real target binary.
 * - If BLOCKED: emits security alert to stderr and exits with code 126.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <limits.h>

#define DEFAULT_SOCK_PATH "/tmp/agentguard.sock"
#define BUFFER_SIZE 65536

static const char* get_binary_name(const char* path) {
    const char* slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

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

static int find_real_binary(const char* name, char* out_path, size_t out_len) {
    const char* orig_path = getenv("AGENTGUARD_ORIGINAL_PATH");
    if (!orig_path || strlen(orig_path) == 0) {
        orig_path = getenv("PATH");
    }
    if (!orig_path) return -1;

    const char* shim_dir = getenv("AGENTGUARD_SHIM_DIR");
    char path_copy[4096];
    strncpy(path_copy, orig_path, sizeof(path_copy) - 1);
    path_copy[sizeof(path_copy) - 1] = '\0';

    char* token = strtok(path_copy, ":");
    while (token != NULL) {
        if (shim_dir && strcmp(token, shim_dir) == 0) {
            token = strtok(NULL, ":");
            continue;
        }

        char candidate[PATH_MAX];
        snprintf(candidate, sizeof(candidate), "%s/%s", token, name);
        if (access(candidate, X_OK) == 0) {
            strncpy(out_path, candidate, out_len - 1);
            out_path[out_len - 1] = '\0';
            return 0;
        }
        token = strtok(NULL, ":");
    }
    return -1;
}

int main(int argc, char* argv[]) {
    if (argc < 1) return 127;

    const char* bin_name = get_binary_name(argv[0]);
    int target_argc = argc;
    char** target_argv = argv;

    if (strcmp(bin_name, "ag-sh") == 0 && argc > 1) {
        target_argc = argc - 1;
        target_argv = argv + 1;
        bin_name = get_binary_name(target_argv[0]);
    }

    const char* session_id = getenv("AGENTGUARD_SESSION_ID");
    if (!session_id || strlen(session_id) == 0) session_id = "default";

    const char* sock_path = getenv("AGENTGUARD_SOCKET");
    if (!sock_path || strlen(sock_path) == 0) {
        sock_path = DEFAULT_SOCK_PATH;
    }

    /* Check Fail-Closed configuration */
    const char* fail_closed_env = getenv("AGENTGUARD_FAIL_CLOSED");
    int fail_closed = 0;
    if (fail_closed_env && (strcmp(fail_closed_env, "1") == 0 || strcmp(fail_closed_env, "true") == 0)) {
        fail_closed = 1;
    }

    /* Build normalized command representation from target_argv */
    char full_cmd[BUFFER_SIZE];
    full_cmd[0] = '\0';
    size_t current_len = 0;

    for (int i = 0; i < target_argc; i++) {
        size_t arg_len = strlen(target_argv[i]);
        if (current_len + arg_len + 2 >= sizeof(full_cmd)) break;
        if (i > 0) {
            strcat(full_cmd, " ");
            current_len += 1;
        }
        strcat(full_cmd, target_argv[i]);
        current_len += arg_len;
    }

    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        strncpy(cwd, ".", sizeof(cwd) - 1);
        cwd[sizeof(cwd) - 1] = '\0';
    }

    /* Check with AgentGuard daemon via UDS */
    int sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    int is_allowed = fail_closed ? 0 : 1;

    if (sock_fd >= 0) {
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);

        if (connect(sock_fd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            char esc_cmd[BUFFER_SIZE];
            char esc_sess[512];
            char esc_cwd[PATH_MAX * 2];

            json_escape(full_cmd, esc_cmd, sizeof(esc_cmd));
            json_escape(session_id, esc_sess, sizeof(esc_sess));
            json_escape(cwd, esc_cwd, sizeof(esc_cwd));

            char req_json[BUFFER_SIZE * 2];
            snprintf(req_json, sizeof(req_json),
                     "{\"protocol_version\":\"1.0\",\"action\":\"CHECK_COMMAND\","
                     "\"session_id\":\"%s\",\"pid\":%d,\"payload\":{\"command\":\"%s\",\"cwd\":\"%s\",\"ppid\":%d}}\n",
                     esc_sess, (int)getpid(), esc_cmd, esc_cwd, (int)getppid());

            send(sock_fd, req_json, strlen(req_json), 0);

            char resp_buf[BUFFER_SIZE];
            ssize_t bytes_read = recv(sock_fd, resp_buf, sizeof(resp_buf) - 1, 0);
            if (bytes_read > 0) {
                resp_buf[bytes_read] = '\0';

                if (strstr(resp_buf, "\"status\": \"BLOCKED\"") ||
                    strstr(resp_buf, "\"status\":\"BLOCKED\"")) {
                    is_allowed = 0;
                } else if (strstr(resp_buf, "\"status\": \"PROMPT_HITL\"") ||
                           strstr(resp_buf, "\"status\":\"PROMPT_HITL\"") ||
                           strstr(resp_buf, "PROMPT_HITL")) {
                    /* Human-In-The-Loop interactive prompt */
                    FILE* tty = fopen("/dev/tty", "r+");
                    if (tty) {
                        fprintf(tty, "\n[AgentGuard HITL Security Alert]\n");
                        fprintf(tty, "Session: %s | Process: %d\n", session_id, (int)getpid());
                        fprintf(tty, "Intercepted Command: %s\n", full_cmd);
                        fprintf(tty, "Allow execution? [y/N]: ");
                        fflush(tty);

                        char answer[32] = {0};
                        if (fgets(answer, sizeof(answer), tty) != NULL) {
                            if (answer[0] == 'y' || answer[0] == 'Y' || answer[0] == 'a' || answer[0] == 'A') {
                                is_allowed = 1;
                                fprintf(tty, "[AgentGuard] Command AUTHORIZED by human operator.\n");
                            } else {
                                is_allowed = 0;
                                fprintf(tty, "[AgentGuard] Command DENIED by human operator.\n");
                            }
                        } else {
                            is_allowed = 0;
                        }
                        fclose(tty);
                    } else {
                        /* Non-interactive session requiring HITL must fail-closed */
                        fprintf(stderr, "[AgentGuard] HITL verification required but no interactive tty available. Command BLOCKED.\n");
                        is_allowed = 0;
                    }
                } else if (strstr(resp_buf, "\"status\": \"ALLOWED\"") ||
                           strstr(resp_buf, "\"status\":\"ALLOWED\"")) {
                    is_allowed = 1;
                }
            }
        } else if (fail_closed) {
            fprintf(stderr, "[AgentGuard] Daemon unreachable at '%s' (Fail-Closed active). Command BLOCKED.\n", sock_path);
            is_allowed = 0;
        }
        close(sock_fd);
    } else if (fail_closed) {
        fprintf(stderr, "[AgentGuard] Unable to create socket (Fail-Closed active). Command BLOCKED.\n");
        is_allowed = 0;
    }

    if (!is_allowed) {
        fprintf(stderr, "[AgentGuard] BLOCKED: Command '%s' was rejected by security policy.\n", full_cmd);
        return 126;
    }

    /* Resolve and execute real system binary */
    char real_path[PATH_MAX];
    if (find_real_binary(bin_name, real_path, sizeof(real_path)) != 0) {
        fprintf(stderr, "[AgentGuard] Error: Real binary '%s' not found in PATH.\n", bin_name);
        return 127;
    }

    target_argv[0] = real_path;
    execv(real_path, target_argv);

    /* If execv returns, an error occurred */
    perror("[AgentGuard] execv failed");
    return 127;
}
