#include <ares.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Define a simple callback function
static void query_callback(void *arg, int status, int timeouts, unsigned char *abuf, int alen) {
  // This is a simple callback function that does nothing
  (void)arg;
  (void)status;
  (void)timeouts;
  (void)abuf;
  (void)alen;
}

int LLVMFuzzerTestOneInput_84(const uint8_t *data, size_t size) {
  ares_channel channel;
  int status = ares_init(&channel);
  if (status != ARES_SUCCESS) {
    return 0;
  }

  unsigned char *qbuf = (unsigned char *)malloc(size);
  if (qbuf == NULL) {
    ares_destroy(channel);
    return 0;
  }
  memcpy(qbuf, data, size);

  // Call the function-under-test
  ares_send(channel, qbuf, (int)size, query_callback, NULL);

  free(qbuf);
  ares_destroy(channel);

  return 0;
}