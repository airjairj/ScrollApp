// pc_server.c
// Compile on Windows (MSVC or MinGW):
// cl pc_server.c /link Ws2_32.lib
// or
// gcc pc_server.c -o pc_server.exe -lws2_32

#define _CRT_SECURE_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "Ws2_32.lib")

#define HOST "127.0.0.1"
#define PORT_STR "55005"
#define PORT 55005
#define RECV_BUF 1024
#define MOUSEEVENTF_WHEEL 0x0800

typedef struct {
    SOCKET sock;
    struct sockaddr_storage addr;
    int addr_len;
} client_info_t;

static void send_wheel(int delta) {
    // mouse_event expects the last parameter as the wheel delta (signed int)
    mouse_event(MOUSEEVENTF_WHEEL, 0, 0, (DWORD)delta, 0);
}

static char *trim_whitespace(char *s) {
    if (!s) return s;
    // left trim
    while (*s && (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')) s++;
    // right trim
    char *end = s + strlen(s) - 1;
    while (end >= s && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')) {
        *end = '\0';
        end--;
    }
    return s;
}

// New helper: process a single (null-terminated) command line.
// Reused by both TCP client thread and UDP thread.
static void process_command_line(char *line) {
    char *trimmed = trim_whitespace(line);
    if (strlen(trimmed) == 0) {
        printf("[DEBUG] Empty command line\n");
        return;
    }
    if (strncmp(trimmed, "SCROLL:", 7) == 0) {
        char *numpart = trimmed + 7;
        numpart = trim_whitespace(numpart);
        long d = strtol(numpart, NULL, 10);
        printf("[DEBUG] SCROLL delta %ld\n", d);
        send_wheel((int)d);
    } else if (_stricmp(trimmed, "DISCONNECT") == 0) {
        // For UDP this doesn't apply; TCP path handles explicit disconnect.
        printf("[DEBUG] DISCONNECT command received (UDP ignored)\n");
    } else {
        printf("[DEBUG] Unknown command: '%s'\n", trimmed);
    }
}

DWORD WINAPI handle_client_thread(LPVOID param) {
    client_info_t *ci = (client_info_t*)param;
    SOCKET conn = ci->sock;

    char addrstr[NI_MAXHOST] = {0}, portstr[NI_MAXSERV] = {0};
    if (getnameinfo((struct sockaddr*)&ci->addr, ci->addr_len,
                    addrstr, sizeof(addrstr), portstr, sizeof(portstr),
                    NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
        printf("[DEBUG] New connection from %s:%s\n", addrstr, portstr);
    } else {
        printf("[DEBUG] New connection (addr unknown)\n");
    }

    // send OK\n
    const char *okmsg = "OK\n";
    if (send(conn, okmsg, (int)strlen(okmsg), 0) == SOCKET_ERROR) {
        printf("[DEBUG] Failed to send OK to client: %d\n", WSAGetLastError());
    } else {
        printf("[DEBUG] Sent OK to client\n");
    }

    char recvbuf[RECV_BUF];
    char linebuf[RECV_BUF * 4];
    int linebuf_len = 0;

    while (1) {
        int r = recv(conn, recvbuf, RECV_BUF, 0);
        if (r == 0) {
            printf("[DEBUG] Connection closed by client\n");
            break;
        } else if (r == SOCKET_ERROR) {
            printf("[DEBUG] recv error: %d\n", WSAGetLastError());
            break;
        }
        printf("[DEBUG] Received chunk (%d bytes)\n", r);

        for (int i = 0; i < r; ++i) {
            char c = recvbuf[i];
            if (c == '\r' || c == '\n') {
                // end of a line
                linebuf[linebuf_len] = '\0';
                printf("[DEBUG] Command line: '%s'\n", linebuf);
                char *trimmed = trim_whitespace(linebuf);
                if (strncmp(trimmed, "SCROLL:", 7) == 0) {
                    char *numpart = trimmed + 7;
                    // allow optional whitespace
                    numpart = trim_whitespace(numpart);
                    long d = strtol(numpart, NULL, 10);
                    printf("[DEBUG] Scrolling by %ld\n", d);
                    send_wheel((int)d);
                } else if (_stricmp(trimmed, "DISCONNECT") == 0) {
                    printf("[DEBUG] DISCONNECT received; closing connection\n");
                    closesocket(conn);
                    free(ci);
                    return 0;
                } else if (strlen(trimmed) == 0) {
                    // empty line, ignore but log
                    printf("[DEBUG] Empty command line\n");
                } else {
                    printf("[DEBUG] Unknown command: '%s'\n", trimmed);
                }
                // reset line buffer
                linebuf_len = 0;
                // If it's CRLF pair, skip handling second char (we handle both as terminators)
            } else {
                if (linebuf_len < (int)sizeof(linebuf) - 1) {
                    linebuf[linebuf_len++] = c;
                } else {
                    // line too long, truncate and reset
                    linebuf[linebuf_len] = '\0';
                    printf("[DEBUG] Line too long, truncated: '%s'\n", linebuf);
                    linebuf_len = 0;
                }
            }
        }
    }

    printf("[DEBUG] Connection cleaned up\n");
    closesocket(conn);
    free(ci);
    return 0;
}

// New: UDP receive thread. Each incoming datagram is treated as a single command (fire-and-forget).
DWORD WINAPI udp_thread_func(LPVOID param) {
    SOCKET udpSock = (SOCKET)(ULONG_PTR)param;
    char recvbuf[RECV_BUF + 1];
    struct sockaddr_storage src;
    int srclen = sizeof(src);
    char addrstr[NI_MAXHOST] = {0}, portstr[NI_MAXSERV] = {0};

    while (1) {
        struct sockaddr_in from4;
        int fromlen = sizeof(from4);
        int r = recvfrom(udpSock, recvbuf, RECV_BUF, 0, (struct sockaddr*)&from4, &fromlen);
        if (r == SOCKET_ERROR) {
            int err = WSAGetLastError();
            // If program is shutting down, socket may be closed; exit thread.
            printf("[DEBUG] UDP recvfrom error: %d\n", err);
            break;
        }
        recvbuf[r] = '\0';
        // optional: print source
        if (getnameinfo((struct sockaddr*)&from4, fromlen, addrstr, sizeof(addrstr), portstr, sizeof(portstr),
                        NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
            printf("[DEBUG] UDP packet from %s:%s (%d bytes)\n", addrstr, portstr, r);
        } else {
            printf("[DEBUG] UDP packet (%d bytes)\n", r);
        }

        // Process the datagram as a single command line (fire-and-forget)
        process_command_line(recvbuf);
    }
    return 0;
}

int main(void) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        fprintf(stderr, "[DEBUG] WSAStartup failed\n");
        return 1;
    }

    int choice = 0;
    while (choice != 1 && choice != 2) {
        printf("Press 1 for udp or press 2 for tcp: ");
        int c = getchar();
        if (c == EOF) {
            fprintf(stderr, "[DEBUG] No input, exiting\n");
            WSACleanup();
            return 1;
        }
        /* consume rest of line */
        int d;
        while ((d = getchar()) != '\n' && d != EOF) { /* skip */ }
        if (c == '1') choice = 1;
        else if (c == '2') choice = 2;
        else printf("Invalid choice. Please press 1 or 2.\n");
    }

    int enable_udp = (choice == 1);
    int enable_tcp = (choice == 2);

    char real_ip[INET6_ADDRSTRLEN] = {0};

    if (enable_tcp) {
        // Determine real IP via UDP connect (only needed for TCP bind to specific address)
        SOCKET s2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (s2 != INVALID_SOCKET) {
            struct sockaddr_in google;
            memset(&google, 0, sizeof(google));
            google.sin_family = AF_INET;
            google.sin_port = htons(80);
            inet_pton(AF_INET, "8.8.8.8", &google.sin_addr);
            if (connect(s2, (struct sockaddr*)&google, sizeof(google)) != SOCKET_ERROR) {
                struct sockaddr_in local;
                int addrlen = sizeof(local);
                if (getsockname(s2, (struct sockaddr*)&local, &addrlen) != SOCKET_ERROR) {
                    inet_ntop(AF_INET, &local.sin_addr, real_ip, sizeof(real_ip));
                    printf("[DEBUG] Real IP determined: %s\n", real_ip);
                } else {
                    printf("[DEBUG] getsockname failed: %d; falling back\n", WSAGetLastError());
                }
            } else {
                printf("[DEBUG] UDP connect failed: %d; falling back\n", WSAGetLastError());
            }
            closesocket(s2);
        } else {
            printf("[DEBUG] UDP socket creation failed: %d; falling back\n", WSAGetLastError());
        }

        if (real_ip[0] == '\0') {
            // fallback to hostname lookup
            char hostname[256];
            if (gethostname(hostname, sizeof(hostname)) == 0) {
                struct addrinfo hints = {0}, *res = NULL;
                hints.ai_family = AF_INET;
                if (getaddrinfo(hostname, NULL, &hints, &res) == 0 && res) {
                    struct sockaddr_in *sin = (struct sockaddr_in*)res->ai_addr;
                    inet_ntop(AF_INET, &sin->sin_addr, real_ip, sizeof(real_ip));
                    printf("[DEBUG] Hostname IP: %s\n", real_ip);
                    freeaddrinfo(res);
                } else {
                    printf("[DEBUG] Hostname lookup failed; using %s\n", HOST);
                    strncpy(real_ip, HOST, sizeof(real_ip)-1);
                }
            } else {
                printf("[DEBUG] gethostname failed; using %s\n", HOST);
                strncpy(real_ip, HOST, sizeof(real_ip)-1);
            }
        }

        printf("PC Server (TCP) Starting, ip: %s\n", real_ip);
    } else {
        printf("PC Server (UDP) Starting\n");
    }

    SOCKET listen_sock = INVALID_SOCKET;
    if (enable_tcp) {
        // Prepare TCP listening socket
        struct addrinfo hints = {0}, *res = NULL;
        hints.ai_family = AF_INET; // IPv4
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_PASSIVE;
        char portbuf[6];
        snprintf(portbuf, sizeof(portbuf), "%d", PORT);

        int rv = getaddrinfo(real_ip, portbuf, &hints, &res);
        if (rv != 0 || res == NULL) {
            fprintf(stderr, "[DEBUG] getaddrinfo failed: %d\n", rv);
            WSACleanup();
            return 1;
        }

        listen_sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (listen_sock == INVALID_SOCKET) {
            fprintf(stderr, "[DEBUG] socket failed: %d\n", WSAGetLastError());
            freeaddrinfo(res);
            WSACleanup();
            return 1;
        }

        BOOL opt = TRUE;
        setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

        if (bind(listen_sock, res->ai_addr, (int)res->ai_addrlen) == SOCKET_ERROR) {
            fprintf(stderr, "[DEBUG] bind failed: %d\n", WSAGetLastError());
            closesocket(listen_sock);
            freeaddrinfo(res);
            WSACleanup();
            return 1;
        }

        freeaddrinfo(res);

        if (listen(listen_sock, SOMAXCONN) == SOCKET_ERROR) {
            fprintf(stderr, "[DEBUG] listen failed: %d\n", WSAGetLastError());
            closesocket(listen_sock);
            WSACleanup();
            return 1;
        }

        printf("Listening (TCP) on %d\n", PORT);
        printf("[DEBUG] Accept loop started\n");
    }

    // Create and bind UDP socket if requested
    SOCKET udp_sock = INVALID_SOCKET;
    if (enable_udp) {
        udp_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (udp_sock == INVALID_SOCKET) {
            printf("[DEBUG] UDP socket creation failed: %d\n", WSAGetLastError());
            // continue anyway (but nothing to do)
        } else {
            struct sockaddr_in bindaddr;
            memset(&bindaddr, 0, sizeof(bindaddr));
            bindaddr.sin_family = AF_INET;
            bindaddr.sin_port = htons(PORT);
            bindaddr.sin_addr.s_addr = INADDR_ANY; // listen on all interfaces
            if (bind(udp_sock, (struct sockaddr*)&bindaddr, sizeof(bindaddr)) == SOCKET_ERROR) {
                printf("[DEBUG] UDP bind failed: %d\n", WSAGetLastError());
                closesocket(udp_sock);
                udp_sock = INVALID_SOCKET;
            } else {
                HANDLE uthread = CreateThread(NULL, 0, udp_thread_func, (LPVOID)(ULONG_PTR)udp_sock, 0, NULL);
                if (uthread) {
                    CloseHandle(uthread); // detached
                    printf("[DEBUG] UDP listener started on port %d\n", PORT);
                } else {
                    printf("[DEBUG] CreateThread for UDP failed: %d\n", (int)GetLastError());
                    closesocket(udp_sock);
                    udp_sock = INVALID_SOCKET;
                }
            }
        }
    }

    // If UDP-only mode, keep main thread alive (UDP thread handles packets)
    if (enable_udp && !enable_tcp) {
        printf("UDP ready. Press Ctrl+C to exit.\n");
        while (1) Sleep(1000);
    }

    // If TCP mode, run accept loop (no UDP)
    if (enable_tcp) {
        while (1) {
            client_info_t *ci = (client_info_t*)malloc(sizeof(client_info_t));
            if (!ci) {
                fprintf(stderr, "[DEBUG] malloc failed\n");
                Sleep(100);
                continue;
            }
            ci->addr_len = sizeof(ci->addr);
            ci->sock = accept(listen_sock, (struct sockaddr*)&ci->addr, &ci->addr_len);
            if (ci->sock == INVALID_SOCKET) {
                printf("[DEBUG] accept failed: %d\n", WSAGetLastError());
                free(ci);
                continue;
            }

            printf("Client connected\n");
            HANDLE th = CreateThread(NULL, 0, handle_client_thread, ci, 0, NULL);
            if (th) {
                CloseHandle(th); // let thread run detached
            } else {
                printf("[DEBUG] CreateThread failed: %d\n", (int)GetLastError());
                closesocket(ci->sock);
                free(ci);
            }
        }
    }

    // Never reached in normal operation
    if (udp_sock != INVALID_SOCKET) closesocket(udp_sock);
    if (listen_sock != INVALID_SOCKET) closesocket(listen_sock);
    WSACleanup();
    return 0;
}