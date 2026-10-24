#include <cstdint>
#include <cstdlib>

extern "C" {
    #include "libical/icalcomponent.h"
}

extern "C" int LLVMFuzzerTestOneInput_131(const uint8_t *data, size_t size) {
    if (size < sizeof(void*)) {
        return 0;
    }

    // Create a pointer from the input data
    const void *input_data = reinterpret_cast<const void*>(data);

    // Call the function-under-test
    bool result = icalcomponent_isa_component(input_data);

    // Use the result in some way to avoid compiler optimizations
    volatile bool use_result = result;
    (void)use_result;

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

    LLVMFuzzerTestOneInput_131(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
