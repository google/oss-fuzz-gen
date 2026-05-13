#include <string.h>
#include <sys/stat.h>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring> // Added for memcpy

extern "C" {
    #include "libical/ical.h"
}

extern "C" int LLVMFuzzerTestOneInput_86(const uint8_t *data, size_t size) {
    // Initialize a memory context
    icalcomponent *component = nullptr;

    // Ensure size is non-zero to create a valid string
    if (size == 0) {
        return 0;
    }

    // Create a temporary buffer to hold the input data as a string
    char *buffer = (char *)malloc(size + 1);
    if (buffer == nullptr) {
        return 0;
    }

    // Copy the input data to the buffer and null-terminate it
    memcpy(buffer, data, size);
    buffer[size] = '\0';

    // Parse the buffer into an icalcomponent
    component = icalparser_parse_string(buffer);

    // Free the buffer as it is no longer needed
    free(buffer);

    if (component != nullptr) {
        // Call the function-under-test
        struct icaltimetype recurrence_id = icalcomponent_get_recurrenceid(component);

        // Free the component
        icalcomponent_free(component);
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

    LLVMFuzzerTestOneInput_86(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
