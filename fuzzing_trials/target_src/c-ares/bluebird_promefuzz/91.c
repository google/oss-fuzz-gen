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

int LLVMFuzzerTestOneInput_91(const uint8_t *Data, size_t Size) {
  ares_channel_t *channel;
  int status;
  char *servers_csv = "8.8.8.8:53,8.8.4.4:53";
  char *name = "example.com";
  char *node = "localhost";
  char *service = "http";
  struct ares_addrinfo_hints hints;
  unsigned char qbuf[512];

  // Initialize c-ares library

  // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 0 of ares_library_init
  status = ares_library_init(ARES_FLAG_NORECURSE);
  // End mutation: Producer.REPLACE_ARG_MUTATOR


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

  // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from ares_set_servers_ports_csv to ares_gethostbyname_file

  // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from ares_set_servers_ports_csv to ares_set_socket_configure_callback

  ares_set_socket_configure_callback(NULL, NULL, (void *)servers_csv);

  // End mutation: Producer.APPEND_MUTATOR

  size_t ret_ares_queue_active_queries_xsxvt = ares_queue_active_queries(channel);
  if (ret_ares_queue_active_queries_xsxvt < 0){
  	return 0;
  }
  unsigned short ret_ares_dns_record_get_flags_waeml = ares_dns_record_get_flags(NULL);
  if (ret_ares_dns_record_get_flags_waeml < 0){
  	return 0;
  }

  int ret_ares_gethostbyname_file_oydxr = ares_gethostbyname_file(channel, servers_csv, (int )ret_ares_dns_record_get_flags_waeml, NULL);
  if (ret_ares_gethostbyname_file_oydxr < 0){
  	return 0;
  }

  // End mutation: Producer.APPEND_MUTATOR


  // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function ares_query with ares_search
  ares_search(channel, name, ns_c_in, ns_t_a, dummy_callback, NULL);
  // End mutation: Producer.REPLACE_FUNC_MUTATOR



  // Fuzz ares_set_servers_ports_csv
  if (Size > 0) {
    char *data_copy = (char *)malloc(Size + 1);
    if (data_copy) {
      memcpy(data_copy, Data, Size);
      data_copy[Size] = '\0'; // Null-terminate the string to avoid overflow
      ares_set_servers_ports_csv(channel, data_copy);

      // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from ares_set_servers_ports_csv to ares_init_options
      int ret_ares_library_init_rdmrp = ares_library_init(ARES_GETSOCK_MAXNUM);
      if (ret_ares_library_init_rdmrp < 0){
      	return 0;
      }
      struct ares_options rtklahwu;
      memset(&rtklahwu, 0, sizeof(rtklahwu));

      int ret_ares_init_options_hllnw = ares_init_options(&channel, &rtklahwu, ret_ares_library_init_rdmrp);
      if (ret_ares_init_options_hllnw < 0){
      	return 0;
      }

      // End mutation: Producer.APPEND_MUTATOR

      free(data_copy);
    }
  }

  // Fuzz ares_getaddrinfo

  // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from ares_query to ares_init_options

  int ret_ares_init_options_zpjoa = ares_init_options(&channel, NULL, ARES_OPT_QUERY_CACHE);
  if (ret_ares_init_options_zpjoa < 0){
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

  // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from ares_query to ares_getsock

  // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 0 of ares_library_init
  int ret_ares_library_init_pytdr = ares_library_init(ARES_NI_IDN_USE_STD3_ASCII_RULES);
  // End mutation: Producer.REPLACE_ARG_MUTATOR


  if (ret_ares_library_init_pytdr < 0){
  	return 0;
  }
  unsigned int ret_ares_dns_rr_get_ttl_lkyyh = ares_dns_rr_get_ttl(NULL);
  if (ret_ares_dns_rr_get_ttl_lkyyh < 0){
  	return 0;
  }

  int ret_ares_getsock_lmtnm = ares_getsock(channel, ret_ares_library_init_pytdr, (int )ret_ares_dns_rr_get_ttl_lkyyh);
  if (ret_ares_getsock_lmtnm < 0){
  	return 0;
  }

  // End mutation: Producer.APPEND_MUTATOR

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