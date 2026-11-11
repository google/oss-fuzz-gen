#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <ares.h>
#include <stdlib.h>
#include <stdio.h>

static void nameinfo_callback(void *arg, int status, int timeouts,
                       char *node, char *service) {
  // To avoid unused parameter warnings, we can use the parameters in a no-op way
  (void)arg;
  (void)status;
  (void)timeouts;
  (void)node;
  (void)service;
}

int LLVMFuzzerTestOneInput_35(const uint8_t* data, size_t size) {
  if (size < sizeof(uint16_t) + sizeof(uint32_t) + sizeof(int)) {
    return 0;
  }

  ares_channel channel;
  if (ares_init(&channel) != ARES_SUCCESS) {
    return 0;
  }

  struct sockaddr_in sa_in;
  struct sockaddr_in6 sa_in6;
  struct sockaddr *sa = NULL;
  ares_socklen_t salen = 0;

  size_t offset = 0;
  int use_ipv4 = data[offset] % 2;
  offset += 1;

  if (use_ipv4) {
    if (size < offset + sizeof(uint16_t) + sizeof(uint32_t)) {
      ares_destroy(channel);
      return 0;
    }
    sa_in.sin_family = AF_INET;
    memcpy(&sa_in.sin_port, &data[offset], sizeof(uint16_t));
    offset += sizeof(uint16_t);
    memcpy(&sa_in.sin_addr.s_addr, &data[offset], sizeof(uint32_t));
    offset += sizeof(uint32_t);
    sa = (struct sockaddr*)&sa_in;
    salen = sizeof(sa_in);
  } else {
    if (size < offset + sizeof(uint16_t) + sizeof(sa_in6.sin6_addr)) {
      ares_destroy(channel);
      return 0;
    }
    sa_in6.sin6_family = AF_INET6;
    memcpy(&sa_in6.sin6_port, &data[offset], sizeof(uint16_t));
    offset += sizeof(uint16_t);
    memcpy(&sa_in6.sin6_addr, &data[offset], sizeof(sa_in6.sin6_addr));
    offset += sizeof(sa_in6.sin6_addr);
    sa = (struct sockaddr*)&sa_in6;
    salen = sizeof(sa_in6);
  }

  if (size < offset + sizeof(int)) {
    ares_destroy(channel);
    return 0;
  }

  int flags_int;
  memcpy(&flags_int, &data[offset], sizeof(int));
  offset += sizeof(int);

  void *arg = NULL;

  ares_getnameinfo(channel, sa, salen, flags_int, nameinfo_callback, arg);

  ares_destroy(channel);
  return 0;
}