#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

extern "C" {
    #include "libical/icalcomponent.h"
}

extern "C" int LLVMFuzzerTestOneInput_132(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient for a pointer
    if (size < sizeof(void*)) {
        return 0;
    }

    // Cast the data to a void pointer
    const void *component = reinterpret_cast<const void*>(data);

    // Call the function-under-test
    bool result = icalcomponent_isa_component(component);

    // Use the result in some way to avoid compiler optimizations
    if (result) {
        // Do something trivial
        volatile bool dummy = result;
        (void)dummy;
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

    LLVMFuzzerTestOneInput_132(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
