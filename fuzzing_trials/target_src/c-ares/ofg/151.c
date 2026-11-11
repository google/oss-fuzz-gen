#include <ares.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_151(const uint8_t *data, size_t size) {
  ares_channel channel;
  int status = ares_init(&channel);
  
  if (status == ARES_SUCCESS && channel != NULL) {
    // Utilize the input data for some operation if needed
    // For example, using ares_query or any other ares function that processes data
    // ares_query(channel, (const char*)data, C_IN, T_A, callback, NULL);
    
    ares_cancel(channel);
    ares_destroy(channel);
  }

  return 0;
}

#ifdef __cplusplus
}
#endif
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

    LLVMFuzzerTestOneInput_151(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
