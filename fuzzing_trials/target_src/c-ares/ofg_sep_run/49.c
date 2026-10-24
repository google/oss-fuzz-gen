#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ares.h>
#include <ares_dns.h>
#include <ares_nameser.h>  // Include this for ns_t_a and ns_c_in

// Define a simple callback function for testing
static void test_callback(void *arg, int status, int timeouts, unsigned char *abuf, int alen) {
  (void)arg;
  (void)status;
  (void)timeouts;
  (void)abuf;
  (void)alen;
  // This is a simple callback that does nothing
}

int LLVMFuzzerTestOneInput_49(const uint8_t *data, size_t size) {
  ares_channel channel;
  ares_library_init(ARES_LIB_INIT_ALL);

  // Initialize the ares channel
  if (ares_init(&channel) != ARES_SUCCESS) {
    return 0;
  }

  // Create a dummy DNS record for testing
  struct ares_dns_record {
    char *name;
    int type;
    int dnsclass;
    unsigned int ttl;
    unsigned char *data;
    size_t data_len;
  } dnsrec;

  dnsrec.name = (char *)data;
  dnsrec.type = ns_t_a;  // Use ns_t_a instead of ARES_T_A
  dnsrec.dnsclass = ns_c_in;  // Use ns_c_in instead of ARES_C_IN
  dnsrec.ttl = 3600;
  dnsrec.data = (unsigned char *)data;
  dnsrec.data_len = size;

  // Prepare a variable for the query ID
  unsigned short qid;

  // Call the function-under-test
  ares_send_dnsrec(channel, (const ares_dns_record_t *)&dnsrec, test_callback, NULL, &qid);

  // Clean up
  ares_destroy(channel);
  ares_library_cleanup();

  return 0;
}