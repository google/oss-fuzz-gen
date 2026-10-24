#include <stddef.h>
#include <stdlib.h>
#include <ares.h>

int LLVMFuzzerTestOneInput_88(const unsigned char *data, size_t size) {
  struct hostent *host = NULL;
  struct ares_addrttl addrttls[5];
  int naddrttls = 5;

  // Call the function-under-test with the provided parameters
  ares_parse_a_reply(data, (int)size, &host, addrttls, &naddrttls);

  // Free the allocated hostent structure if it was populated
  if (host) {
    ares_free_hostent(host);
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

    LLVMFuzzerTestOneInput_88(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
