#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <ares.h>

/* Fuzzer entry point */
int LLVMFuzzerTestOneInput_7(const uint8_t *data, size_t size) {
  ares_channel channel;
  int status;

  /* Initialize the ares library */
  status = ares_library_init(ARES_LIB_INIT_ALL);
  if (status != ARES_SUCCESS) {
    return 0;
  }

  /* Initialize the ares channel */
  status = ares_init(&channel);
  if (status != ARES_SUCCESS) {
    ares_library_cleanup();
    return 0;
  }

  /* Call the function-under-test */
  /* Assuming ares_queue_active_queries is a valid function to test */
  size_t active_queries = ares_queue_active_queries(&channel);

  /* Clean up the ares channel */
  ares_destroy(channel);

  /* Clean up the ares library */
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

    LLVMFuzzerTestOneInput_7(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
