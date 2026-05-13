#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <ares.h>
#include <ares_dns.h>
#include <ares_nameser.h> // Include the necessary header for ns_type and ns_class

static void dummy_callback(void *arg, int status, int timeouts, unsigned char *abuf, int alen) {
  (void)arg;      /* Suppress unused parameter warning */
  (void)status;   /* Suppress unused parameter warning */
  (void)timeouts; /* Suppress unused parameter warning */
  (void)abuf;     /* Suppress unused parameter warning */
  (void)alen;     /* Suppress unused parameter warning */
}

int LLVMFuzzerTestOneInput_75(const uint8_t *data, size_t size) {
  if (size < 1) return 0;

  ares_channel channel;
  if (ares_library_init(ARES_LIB_INIT_ALL) != ARES_SUCCESS) {
    return 0;
  }

  if (ares_init(&channel) != ARES_SUCCESS) {
    ares_library_cleanup();
    return 0;
  }

  char name[256];
  strncpy(name, (const char *)data, sizeof(name) - 1);
  name[sizeof(name) - 1] = '\0';

  ns_class dnsclass = (ns_class)(data[0] % 3); // Randomly choose a class
  ns_type type = (ns_type)(data[0] % 5); // Randomly choose a type

  unsigned short qid = 0;
  void *arg = NULL;

  ares_query(channel, name, dnsclass, type, dummy_callback, arg);

  ares_destroy(channel);
  ares_library_cleanup();

  return 0;
}