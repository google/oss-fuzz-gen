#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "ares.h"

static void ares_getaddrinfo_callback(void *arg, int status, int timeouts, struct ares_addrinfo *res) {
  (void)arg;
  (void)timeouts;
  if (res) {
    ares_freeaddrinfo(res);
  }
}

int LLVMFuzzerTestOneInput_1(const uint8_t *Data, size_t Size) {
  if (Size < sizeof(int)) {
    return 0;
  }

  int init_flags = *(int *)Data;
  Data += sizeof(int);
  Size -= sizeof(int);

  if (ares_library_init(init_flags) != ARES_SUCCESS) {
    return 0;
  }

  const char *error_message;
  if (Size >= sizeof(int)) {
    int error_code = *(int *)Data;
    error_message = ares_strerror(error_code);
    (void)error_message;
    Data += sizeof(int);
    Size -= sizeof(int);
  }

  ares_channel_t *channel = NULL;
  struct ares_options options;
  memset(&options, 0, sizeof(options));
  int optmask = 0;

  // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 2 of ares_init_options
  if (ares_init_options(&channel, &options, ARES_OPT_EVENT_THREAD) == ARES_SUCCESS) {
  // End mutation: Producer.REPLACE_ARG_MUTATOR
    if (Size >= sizeof(int)) {
      int error_code = *(int *)Data;
      error_message = ares_strerror(error_code);

      // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from ares_strerror to ares_gethostbyname_file
      // Ensure dataflow is valid (i.e., non-null)
      if (!channel) {
      	return 0;
      }
      ares_status_t ret_ares_reinit_cgvtq = ares_reinit(channel);
      // Ensure dataflow is valid (i.e., non-null)
      if (!channel) {
      	return 0;
      }
      int ret_ares_gethostbyname_file_ifozh = ares_gethostbyname_file(channel, &error_message, ARES_AI_NUMERICSERV, NULL);
      if (ret_ares_gethostbyname_file_ifozh < 0){
      	return 0;
      }
      // End mutation: Producer.APPEND_MUTATOR
      
      (void)error_message;
      Data += sizeof(int);
      Size -= sizeof(int);
    }

    char *servers_csv = ares_get_servers_csv(channel);
    if (servers_csv) {
      ares_free_string(servers_csv);
    }

    // Ensure node and service are null-terminated
    const char *node = NULL;
    const char *service = NULL;
    if (Size > 0) {
      size_t node_len = strnlen((const char *)Data, Size);
      if (node_len < Size) {
        node = (const char *)Data;
        Data += node_len + 1;
        Size -= (node_len + 1);
      }
    }

    if (Size > 0) {
      size_t service_len = strnlen((const char *)Data, Size);
      if (service_len < Size) {
        service = (const char *)Data;
        Data += service_len + 1;
        Size -= (service_len + 1);
      }
    }

    struct ares_addrinfo_hints hints;
    memset(&hints, 0, sizeof(hints));

    if (node || service) { // Ensure at least one of them is non-null
      ares_getaddrinfo(channel, node, service, &hints, ares_getaddrinfo_callback, NULL);
    
      // Begin mutation: Producer.SPLICE_MUTATOR - Spliced data flow from ares_getaddrinfo to ares_init using the plateau pool
      // Ensure dataflow is valid (i.e., non-null)
      if (!channel) {
      	return 0;
      }

      // Begin mutation: Producer.SPLICE_MUTATOR - Spliced data flow from ares_getaddrinfo to ares_set_servers_csv using the plateau pool
      // Ensure dataflow is valid (i.e., non-null)
      if (!channel) {
      	return 0;
      }
      int ret_ares_set_servers_csv_uydnf = ares_set_servers_csv(channel, &servers_csv);
      if (ret_ares_set_servers_csv_uydnf < 0){
      	return 0;
      }
      // End mutation: Producer.SPLICE_MUTATOR
      
      int ret_ares_init_vctqd = ares_init(&channel);
      if (ret_ares_init_vctqd < 0){
      	return 0;
      }
      // End mutation: Producer.SPLICE_MUTATOR
      
}

    ares_destroy(channel);
  }


  // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from ares_init_options to ares_inet_ntop
  size_t ret_ares_dns_record_query_cnt_slbgx = ares_dns_record_query_cnt(NULL);
  if (ret_ares_dns_record_query_cnt_slbgx < 0){
  	return 0;
  }
  char ret_ares_dns_section_tostr_wzkgt = ares_dns_section_tostr(0);
  // Ensure dataflow is valid (i.e., non-null)
  if (!channel) {
  	return 0;
  }
  char ret_ares_inet_ntop_wiaoh = ares_inet_ntop((int )ret_ares_dns_record_query_cnt_slbgx, (void *)channel, &ret_ares_dns_section_tostr_wzkgt, 0);
  // End mutation: Producer.APPEND_MUTATOR
  
  ares_library_cleanup();
  return 0;
}
#ifdef INC_MAIN
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
int main(int argc, char *argv[])
{
    FILE *f;
    uint8_t *data = NULL;
    long size;

    if(argc < 2)
        exit(0);

    f = fopen(argv[1], "rb");
    if(f == NULL)
        exit(0);

    fseek(f, 0, SEEK_END);

    size = ftell(f);
    rewind(f);

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_1(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
