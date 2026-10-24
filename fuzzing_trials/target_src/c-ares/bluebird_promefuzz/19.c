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

int LLVMFuzzerTestOneInput_19(const uint8_t *Data, size_t Size) {
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

  if (ares_init_options(&channel, &options, optmask) == ARES_SUCCESS) {
    if (Size >= sizeof(int)) {
      int error_code = *(int *)Data;
      error_message = ares_strerror(error_code);

      // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from ares_strerror to ares_gethostbyname
      // Ensure dataflow is valid (i.e., non-null)
      if (!channel) {
      	return 0;
      }
      size_t ret_ares_queue_active_queries_cbzun = ares_queue_active_queries(channel);
      if (ret_ares_queue_active_queries_cbzun < 0){
      	return 0;
      }
      unsigned int ret_ares_dns_rr_get_ttl_rqvhw = ares_dns_rr_get_ttl(NULL);
      if (ret_ares_dns_rr_get_ttl_rqvhw < 0){
      	return 0;
      }
      char ret_ares_dns_rec_type_tostr_nzvng = ares_dns_rec_type_tostr(0);
      // Ensure dataflow is valid (i.e., non-null)
      if (!channel) {
      	return 0;
      }
      ares_gethostbyname(channel, &error_message, (int )ret_ares_dns_rr_get_ttl_rqvhw, NULL, (void *)&ret_ares_dns_rec_type_tostr_nzvng);
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

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from ares_get_servers_csv to ares_dns_class_fromstr
    ares_dns_class_t ret_ares_dns_rr_get_class_bmtaa = ares_dns_rr_get_class(NULL);
    ares_bool_t ret_ares_dns_class_fromstr_riray = ares_dns_class_fromstr(&ret_ares_dns_rr_get_class_bmtaa, &servers_csv);
    // End mutation: Producer.APPEND_MUTATOR
    
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
    }

    ares_destroy(channel);
  }

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

    LLVMFuzzerTestOneInput_19(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
