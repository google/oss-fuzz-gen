#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <ares.h>
#include <ares_dns.h>  /* Include additional headers if needed by ares */

int LLVMFuzzerTestOneInput_133(const uint8_t *data, size_t size) {
  if (size == 0) {
    return 0;
  }

  ares_channel channel;
  struct ares_options options;
  int optmask = 0;
  int status = ares_init_options(&channel, &options, optmask);

  if (status != ARES_SUCCESS) {
    return 0;
  }

  int numsocks = ARES_GETSOCK_MAXNUM;
  ares_socket_t socks[ARES_GETSOCK_MAXNUM];

  /* Call the function-under-test */
  ares_getsock(channel, socks, numsocks);

  ares_destroy(channel);
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

    LLVMFuzzerTestOneInput_133(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
