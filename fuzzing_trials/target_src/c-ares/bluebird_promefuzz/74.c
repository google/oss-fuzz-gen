#include <stdint.h>
#include "stddef.h"
#include <string.h>
#include <stdlib.h>
#include "stdio.h"
#include "ares.h"
#include <arpa/nameser.h> // Include this for ns_c_in and ns_t_a

static void dummy_callback(void *arg, int status, int timeouts, unsigned char *abuf, int alen) {
  // Dummy callback function to handle responses
}

static void addrinfo_callback(void *arg, int status, int timeouts, struct ares_addrinfo *res) {
  // Free the addrinfo result to avoid memory leaks
  if (res) {
    ares_freeaddrinfo(res);
  }
}

int LLVMFuzzerTestOneInput_74(const uint8_t *Data, size_t Size) {
  ares_channel_t *channel;
  int status;
  char *servers_csv = "8.8.8.8:53,8.8.4.4:53";
  char *name = "example.com";
  char *node = "localhost";
  char *service = "http";
  struct ares_addrinfo_hints hints;
  unsigned char qbuf[512];

  // Initialize c-ares library
  status = ares_library_init(ARES_LIB_INIT_ALL);
  if (status != ARES_SUCCESS) {
    return 0;
  }

  // Initialize the ares channel
  status = ares_init(&channel);
  if (status != ARES_SUCCESS) {
    ares_library_cleanup();
    return 0;
  }

  // Set servers using CSV
  ares_set_servers_ports_csv(channel, servers_csv);

  // Fuzz ares_query
  ares_query(channel, name, ns_c_in, ns_t_a, dummy_callback, NULL);

  // Fuzz ares_set_servers_ports_csv
  if (Size > 0) {
    char *data_copy = (char *)malloc(Size + 1);
    if (data_copy) {
      memcpy(data_copy, Data, Size);
      data_copy[Size] = '\0'; // Null-terminate the string to avoid overflow
      ares_set_servers_ports_csv(channel, data_copy);
      free(data_copy);
    }
  }

  // Fuzz ares_getaddrinfo

  // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from ares_query to ares_init_options
  char ret_ares_version_jbfbe = ares_version(&status);
  struct ares_options jhvqquro;
  memset(&jhvqquro, 0, sizeof(jhvqquro));

  int ret_ares_init_options_qcxbe = ares_init_options(&channel, &jhvqquro, status);
  if (ret_ares_init_options_qcxbe < 0){
  	return 0;
  }

  // End mutation: Producer.APPEND_MUTATOR

  memset(&hints, 0, sizeof(hints));
  ares_getaddrinfo(channel, node, service, &hints, addrinfo_callback, NULL);

  // Fuzz ares_search

  // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function ares_search with ares_query
  ares_query(channel, name, ns_c_in, ns_t_a, dummy_callback, NULL);
  // End mutation: Producer.REPLACE_FUNC_MUTATOR



  // Fuzz ares_get_servers_csv
  char *csv = ares_get_servers_csv(channel);
  if (csv) {
    free(csv);
  }

  // Fuzz ares_send
  if (Size > 0 && Size <= sizeof(qbuf)) {
    memcpy(qbuf, Data, Size);
    ares_send(channel, qbuf, Size, dummy_callback, NULL);
  }

  // Cleanup
  ares_destroy(channel);
  ares_library_cleanup();

  return 0;
}