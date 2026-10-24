#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <ares.h>

static void dns_callback(void *arg, int status, int timeouts, unsigned char *abuf, int alen) {
  /* Callback function to handle the response */
  (void)arg;
  (void)status;
  (void)timeouts;
  (void)abuf;
  (void)alen;
}

int LLVMFuzzerTestOneInput_76(const uint8_t *data, size_t size) {
  if (size < 1) return 0;

  ares_channel channel;
  struct ares_options options;
  int optmask = 0;
  int status = ares_init_options(&channel, &options, optmask);
  if (status != ARES_SUCCESS) {
    return 0;
  }

  const char *name = "example.com";
  ares_dns_class_t dnsclass = (ares_dns_class_t)(data[0] % 3); // Randomly choose a class
  ares_dns_rec_type_t type = (ares_dns_rec_type_t)(data[0] % 5); // Randomly choose a type
  unsigned short qid = 0;

  ares_query_dnsrec(channel, name, dnsclass, type, dns_callback, NULL, &qid);

  ares_destroy(channel);
  return 0;
}