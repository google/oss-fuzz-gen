#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include "/src/htslib/htslib/hts.h"

// Declare the functions if they are part of a custom implementation
void hts_lib_initialize(const uint8_t *data, size_t size) {
    // Implement the initialization logic here
    printf("Initializing with data of size %zu\n", size);
}

void hts_lib_shutdown_91() {
    // Implement the shutdown logic here
    printf("Shutting down\n");
}

int LLVMFuzzerTestOneInput_91(const uint8_t *data, size_t size) {
    // Simulate library initialization with input data
    hts_lib_initialize(data, size);

    // Call the function-under-test
    hts_lib_shutdown_91();

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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_91(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
