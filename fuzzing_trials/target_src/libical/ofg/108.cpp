#include <libical/ical.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_108(const uint8_t *data, size_t size) {
    // Ensure the input data is null-terminated for safe string operations
    char *ical_data = static_cast<char*>(malloc(size + 1));
    if (ical_data == nullptr) {
        return 0; // Out of memory, exit early
    }
    memcpy(ical_data, data, size);
    ical_data[size] = '\0';

    // Parse the input data into an icalcomponent
    icalcomponent *component = icalparser_parse_string(ical_data);

    // Ensure the component is not NULL
    if (component != nullptr) {
        // Call the function-under-test
        int error_count = icalcomponent_count_errors(component);
        
        // Optionally, you can use the error_count in some way, e.g., logging
        // printf("Error count: %d\n", error_count);

        // Clean up
        icalcomponent_free(component);
    }

    free(ical_data);
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

    LLVMFuzzerTestOneInput_108(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
