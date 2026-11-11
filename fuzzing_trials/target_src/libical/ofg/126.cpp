#include <stdint.h>
#include <stddef.h>
#include <stdlib.h> // For malloc and free
#include <string.h> // For memcpy

extern "C" {
    #include <libical/ical.h>
}

extern "C" int LLVMFuzzerTestOneInput_126(const uint8_t *data, size_t size) {
    // Initialize a memory context
    icalcomponent *component = nullptr;

    // Ensure the data is not null and has a reasonable size
    if (data != nullptr && size > 0) {
        // Create a temporary buffer to hold the data
        char *buffer = (char *)malloc(size + 1);
        if (buffer == nullptr) {
            return 0;
        }

        // Copy the data into the buffer and null-terminate it
        memcpy(buffer, data, size);
        buffer[size] = '\0';

        // Parse the buffer into an icalcomponent
        component = icalparser_parse_string(buffer);

        // Free the buffer
        free(buffer);
    }

    // Fuzz the function-under-test
    if (component != nullptr) {
        const char *relcalid = icalcomponent_get_relcalid(component);
        // Use the result in some way to avoid compiler optimizations
        if (relcalid != nullptr) {
            // Do something with relcalid, e.g., print or log
        }

        // Clean up the icalcomponent
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

    LLVMFuzzerTestOneInput_126(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
