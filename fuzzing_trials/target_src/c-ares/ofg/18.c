#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ares.h>
#include <ares_dns.h>
#include <ares_dns_record.h>

/* Define the full structure of ares_dns_record_t */
struct ares_dns_record {
    char *name;
    int type;
    int class_;
    unsigned int ttl;
    unsigned char *data;
    size_t data_len;
};

int LLVMFuzzerTestOneInput_18(const uint8_t *data, size_t size) {
  /* Initialize ares library */
  ares_library_init(ARES_LIB_INIT_ALL);

  /* Create a dummy DNS record */
  struct ares_dns_record *dnsrec = (struct ares_dns_record *)malloc(sizeof(struct ares_dns_record));
  if (dnsrec == NULL) {
    ares_library_cleanup();
    return 0;
  }

  /* Initialize the DNS record with some dummy values */
  dnsrec->name = strdup("example.com");
  dnsrec->type = ARES_REC_TYPE_A;
  dnsrec->class_ = ARES_CLASS_IN;
  dnsrec->ttl = 3600;
  dnsrec->data = (unsigned char *)malloc(size);
  if (dnsrec->data != NULL) {
    memcpy(dnsrec->data, data, size);
    dnsrec->data_len = size;
  } else {
    free(dnsrec);
    ares_library_cleanup();
    return 0;
  }

  /* Define a section and index to use */
  ares_dns_section_t sect = ARES_SECTION_ANSWER;
  size_t idx = 0;

  /* Call the function-under-test */
  ares_dns_rr_t *rr = ares_dns_record_rr_get(dnsrec, sect, idx);

  /* Free resources */
  if (rr != NULL) {
    free(rr);
  }
  free(dnsrec->data);
  free(dnsrec->name);
  free(dnsrec);

  /* Cleanup ares library */
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

    LLVMFuzzerTestOneInput_18(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
