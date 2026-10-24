#include <sys/stat.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "ares.h"

int LLVMFuzzerTestOneInput_17(const uint8_t *data, size_t size) {
  ares_channel channel;
  int status;
  
  /* Initialize ares library */
  status = ares_library_init(ARES_LIB_INIT_ALL);
  if (status != ARES_SUCCESS) {
    return 0;
  }

  /* Initialize ares channel */
  status = ares_init(&channel);
  if (status != ARES_SUCCESS) {
    ares_library_cleanup();
    return 0;
  }

  /* Ensure the CSV string is null-terminated */
  char *csv = (char *)malloc(size + 1);
  if (csv == NULL) {
    ares_destroy(channel);
    ares_library_cleanup();
    return 0;
  }
  memcpy(csv, data, size);
  csv[size] = '\0';

  /* Call the function under test */
  ares_set_servers_ports_csv(channel, csv);

  /* Clean up */

  // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from ares_set_servers_ports_csv to ares_dns_class_fromstr
  ares_dns_class_t ret_ares_dns_rr_get_class_qwzxe = ares_dns_rr_get_class(NULL);
  // Ensure dataflow is valid (i.e., non-null)
  if (!csv) {
  	return 0;
  }
  ares_bool_t ret_ares_dns_class_fromstr_zskdn = ares_dns_class_fromstr(&ret_ares_dns_rr_get_class_qwzxe, csv);
  // End mutation: Producer.APPEND_MUTATOR
  
  free(csv);
  ares_destroy(channel);
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

    LLVMFuzzerTestOneInput_17(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
