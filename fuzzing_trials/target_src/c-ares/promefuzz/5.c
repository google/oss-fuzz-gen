// This fuzz driver is generated for library cares, aiming to fuzz the following functions:
// ares_library_init at ares_library_init.c:108:5 in ares.h
// ares_init at ares_init.c:67:5 in ares.h
// ares_library_cleanup at ares_library_init.c:139:6 in ares.h
// ares_dup at ares_init.c:455:5 in ares.h
// ares_set_local_ip4 at ares_init.c:546:6 in ares.h
// ares_set_local_ip6 at ares_init.c:557:6 in ares.h
// ares_set_local_dev at ares_init.c:568:6 in ares.h
// ares_query_dnsrec at ares_query.c:115:15 in ares.h
// ares_query at ares_query.c:133:6 in ares.h
// ares_destroy at ares_destroy.c:32:6 in ares.h
// ares_destroy at ares_destroy.c:32:6 in ares.h
// ares_library_cleanup at ares_library_init.c:139:6 in ares.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ares.h>
#include <arpa/nameser.h> // Include for ns_c_in and ns_t_a

static void dns_callback(void *arg, int status, int timeouts, const unsigned char *abuf, int alen) {
  (void)arg;
  (void)status;
  (void)timeouts;
  (void)abuf;
  (void)alen;
}

static void dnsrec_callback(void *arg, ares_status_t status, unsigned long timeouts, const struct ares_dns_record *dnsrec) {
  (void)arg;
  (void)status;
  (void)timeouts;
  (void)dnsrec;
}

int LLVMFuzzerTestOneInput_5(const uint8_t *Data, size_t Size) {
  if (Size < sizeof(ares_channel_t*)) {
    return 0;
  }

  ares_channel channel = NULL;
  ares_channel dup_channel = NULL;
  int status;
  unsigned short qid;

  // Initialize ares library
  ares_library_init(ARES_LIB_INIT_ALL);

  // Create a channel
  status = ares_init(&channel);
  if (status != ARES_SUCCESS) {
    ares_library_cleanup();
    return 0;
  }

  // Duplicate the channel
  ares_dup(&dup_channel, channel);

  // Set local IPv4 address
  unsigned int local_ip4 = 0x7f000001; // 127.0.0.1 in network byte order
  ares_set_local_ip4(channel, local_ip4);

  // Set local IPv6 address
  unsigned char local_ip6[16] = {0};
  ares_set_local_ip6(channel, local_ip6);

  // Set local device
  const char *local_dev_name = "lo";
  ares_set_local_dev(channel, local_dev_name);

  // Perform DNS queries
  const char *name = "example.com";
  ares_query_dnsrec(channel, name, ns_c_in, ns_t_a, dnsrec_callback, NULL, &qid);
  ares_query(channel, name, ns_c_in, ns_t_a, dns_callback, NULL);

  // Clean up
  ares_destroy(channel);
  ares_destroy(dup_channel);
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

    LLVMFuzzerTestOneInput_5(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
