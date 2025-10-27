/*
 * Copyright (c) 2017-2024 Free Software Foundation, Inc.
 *
 * This file is part of libwget.
 *
 * Libwget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Libwget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with libwget.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>

#include <dirent.h> // opendir, readdir
#include <stdint.h> // uint8_t
#include <stdio.h>  // fmemopen
#include <string.h> // strncmp
#include <sys/types.h>

#include "fuzzer.h"
#include "wget.h"

static uint8_t *g_data;
static size_t g_size;
static bool fuzzing;
static int mode;
static int connect_fd;

#if defined HAVE_DLFCN_H && defined HAVE_FMEMOPEN
#include <dlfcn.h>
#include <netdb.h>
#include <sys/socket.h>
#if defined __OpenBSD__ || defined __FreeBSD__
#include <netinet/in.h>
#endif
#ifdef RTLD_NEXT /* Not defined e.g. on CygWin */
struct combined {
  struct addrinfo ai;
  struct sockaddr_in in_addr;
};
int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) {
  if (fuzzing) {
    // glibc 2.24 does no extra free() for in_addr
    struct combined aic = {
        .in_addr.sin_family = AF_INET,
        .in_addr.sin_port = 80,
        .ai.ai_flags = 0,
        .ai.ai_family = AF_INET,
        .ai.ai_socktype = SOCK_STREAM,
        .ai.ai_protocol = 0,
        .ai.ai_canonname = NULL,
        .ai.ai_next = NULL,
        .ai.ai_addrlen = sizeof(struct sockaddr_in),
    };

    aic.ai.ai_addr = (struct sockaddr *)&aic.in_addr;
    *res = (struct addrinfo *)wget_memdup(&aic, sizeof(aic));
    return 0;
  }

  int (*libc_getaddrinfo)(const char *, const char *, const struct addrinfo *, struct addrinfo **) = (int (*)(const char *, const char *, const struct addrinfo *, struct addrinfo **))dlsym(RTLD_NEXT, "getaddrinfo");

  return libc_getaddrinfo(node, service, hints, res);
}
void freeaddrinfo(struct addrinfo *res) {
  struct addrinfo *ai, *cur;
  if (fuzzing) {
    ai = res;
    while (ai) {
      cur = ai;
      ai = ai->ai_next;
      wget_free(cur);
    }
    return;
  }

  void (*libc_freeaddrinfo)(struct addrinfo *res) = (void (*)(struct addrinfo *res))dlsym(RTLD_NEXT, "getaddrinfo");

  libc_freeaddrinfo(res);
}

#if defined __OpenBSD__ || defined __FreeBSD__
int getnameinfo(const struct sockaddr *addr, socklen_t addrlen, char *host, size_t hostlen, char *serv, size_t servlen, int flags)
#else
int getnameinfo(const struct sockaddr *addr, socklen_t addrlen, char *host, socklen_t hostlen, char *serv, socklen_t servlen, int flags)
#endif
{
  if (fuzzing)
    return -1;

  int (*libc_getnameinfo)(const struct sockaddr *, socklen_t, char *, socklen_t, char *, socklen_t, int) = (int (*)(const struct sockaddr *, socklen_t, char *, socklen_t, char *, socklen_t, int))dlsym(RTLD_NEXT, "getnameinfo");

  return libc_getnameinfo(addr, addrlen, host, hostlen, serv, servlen, flags);
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
  if (connect_fd == -1) {
    connect_fd = sockfd;
    return 0;
  }

  int (*libc_connect)(int, const struct sockaddr *, socklen_t) = (int (*)(int, const struct sockaddr *, socklen_t))dlsym(RTLD_NEXT, "connect");

  return libc_connect(sockfd, addr, addrlen);
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {
  if (sockfd == connect_fd) {
    if (mode == 1 && len > 1) {
      len = 1;
    }

    if (len > g_size)
      len = g_size;
    memcpy(buf, g_data, len);
    g_size -= len;
    return len;
  }

  int (*libc_recvfrom)(int, void *, size_t, int, struct sockaddr *, socklen_t *) = (int (*)(int, void *, size_t, int, struct sockaddr *, socklen_t *))dlsym(RTLD_NEXT, "recvfrom");

  return libc_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {
  if (connect_fd == -1) {
    connect_fd = sockfd;
    return (ssize_t)len;
  }

  int (*libc_sendto)(int, const void *, size_t, int, const struct sockaddr *, socklen_t) = (int (*)(int, const void *, size_t, int, const struct sockaddr *, socklen_t))dlsym(RTLD_NEXT, "sendto");

  return libc_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
  if (sockfd == connect_fd)
    return (ssize_t)len;

  int (*libc_send)(int, const void *, size_t, int) = (int (*)(int, const void *, size_t, int))dlsym(RTLD_NEXT, "sendto");

  return libc_send(sockfd, buf, len, flags);
}
#endif
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static const char *header[3] = {"HTTP/1.1 200 OK\r\n"
                                  "Host: a\r\n"
                                  "Transfer-Encoding: chunked\r\n"
                                  "Connection: keep-alive\r\n\r\n",
                                  "HTTP/1.1 200 OK\r\n"
                                  "Host: a\r\n"
                                  "Content-Length: 10\r\n"
                                  "Connection: keep-alive\r\n\r\n",
                                  ("HTTP/1.1 200 OK\r\n"
                                   "Host: a\r\n\r\n")};

  if (size > 256) // same as max_len = 4096 in .options file
    return 0;

  fuzzing = 1;
  wget_iri *uri = wget_iri_parse("http://example.com", NULL);
  wget_tcp_set_timeout(NULL, 0);         // avoid to call select or poll
  wget_tcp_set_connect_timeout(NULL, 0); // avoid to call select or poll

  for (mode = 0; mode < 2; mode++) {
    for (int type = 0; type < 3; type++) {
      size_t hlen = strlen(header[type]);

      g_size = hlen + size;
      g_data = (uint8_t *)malloc(g_size);
      memcpy(g_data, header[type], hlen);
      memcpy(g_data + hlen, data, size);

      connect_fd = -1;

      wget_http_request *req = wget_http_create_request(uri, "GET");
      wget_http_connection *conn = NULL;

      // wget_http_add_header(req, "User-Agent", "TheUserAgent/0.5");

      if (wget_http_open(&conn, uri) == WGET_E_SUCCESS) {
        if (wget_http_send_request(conn, req) == WGET_E_SUCCESS) {
          wget_http_response *resp = wget_http_get_response(conn);
          wget_http_free_response(&resp);
        }
        wget_http_close(&conn);
      }

      wget_http_free_request(&req);
      free(g_data);
    }
  }

  wget_iri_free(&uri);
  fuzzing = 0;

  return 0;
}
