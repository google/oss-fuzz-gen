#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <ares.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*ares_sock_config_callback)(ares_socket_t, int, void *);

int dummy_socket_configure_callback(ares_socket_t socket_fd, int type, void *data) {
  // This is a dummy callback function for testing purposes.
  (void)socket_fd;
  (void)type;
  (void)data;
  return 0;
}

int LLVMFuzzerTestOneInput_80(const uint8_t *data, size_t size) {
  ares_channel channel;
  int status = ares_init(&channel);
  if (status != ARES_SUCCESS) {
    return 0;
  }

  // Use a portion of the input data as the dummy data for the callback.
  void *callback_data = (void *)data;

  // Set the socket configure callback.
  ares_set_socket_configure_callback(channel, dummy_socket_configure_callback, callback_data);

  // Clean up the ares channel.
  ares_destroy(channel);

  return 0;
}

#ifdef __cplusplus
}
#endif