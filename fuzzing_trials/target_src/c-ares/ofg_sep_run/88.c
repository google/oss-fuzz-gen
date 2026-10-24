#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <ares.h>
#include <netdb.h> // Include for struct hostent
#include <sys/socket.h> // Include for AF_INET

int LLVMFuzzerTestOneInput_88(const uint8_t *data, size_t size) {
  /* Initialize the ares library */
  ares_library_init(ARES_LIB_INIT_ALL);

  /* Create an ares channel */
  ares_channel channel;
  if (ares_init(&channel) != ARES_SUCCESS) {
    return 0;
  }

  /* Ensure that the data is null-terminated to be used as a string */
  char *name = (char *)malloc(size + 1);
  if (name == NULL) {
    ares_destroy(channel);
    return 0;
  }
  memcpy(name, data, size);
  name[size] = '\0';

  /* Define a hostent structure */
  struct hostent *host = NULL;

  /* Call the function-under-test */
  int family = AF_INET; // Use AF_INET as a default family
  ares_gethostbyname_file(&channel, name, family, &host);

  /* Clean up */
  if (host) {
    ares_free_hostent(host);
  }
  free(name);
  ares_destroy(channel);
  ares_library_cleanup();

  return 0;
}