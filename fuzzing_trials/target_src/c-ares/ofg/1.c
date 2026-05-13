#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ares.h>
#include <ares_nameser.h>

int LLVMFuzzerTestOneInput_1(const uint8_t *data, size_t size) {
  /* Define and initialize parameters for ares_create_query */
  const char *name = "example.com";  /* Use a valid domain name */
  int dnsclass = C_IN;  /* Internet class */
  int type = T_A;  /* Type A record */
  unsigned short id = 12345;  /* Arbitrary ID */
  int rd = 1;  /* Recursion desired */
  unsigned char *buf = NULL;  /* Buffer for the query */
  int buflen = 0;  /* Length of the buffer */
  int max_udp_size = 512;  /* Standard UDP size for DNS */

  /* Use the input data in some way to influence the query creation process */
  if (size > 0) {
    id = data[0];  /* Use the first byte of data to set the ID */
  }

  /* Call the function-under-test */
  int result = ares_create_query(name, dnsclass, type, id, rd, &buf, &buflen, max_udp_size);

  /* Free allocated buffer if it was successfully created */
  if (buf != NULL) {
    free(buf);
  }

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
