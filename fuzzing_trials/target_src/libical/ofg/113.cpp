#include <libical/ical.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>  // For malloc and free
#include <string.h>  // For memcpy

extern "C" {
    // Include necessary C headers, source files, functions, and code here.
    // This ensures the C library functions are correctly linked with the C++ code.
}

extern "C" int LLVMFuzzerTestOneInput_113(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient for creating a valid icalcomponent
    if (size < 1) {
        return 0;
    }

    // Create a string from the input data
    char *ical_str = (char *)malloc(size + 1);
    if (!ical_str) {
        return 0;
    }
    memcpy(ical_str, data, size);
    ical_str[size] = '\0';

    // Parse the string into an icalcomponent
    icalcomponent *component = icalparser_parse_string(ical_str);
    free(ical_str);

    if (!component) {
        return 0;
    }

    // Initialize an icalcompiter
    icalcompiter iter;
    iter = icalcomponent_begin_component(component, ICAL_ANY_COMPONENT);

    // Call the function-under-test
    icalcomponent *next_component = icalcompiter_next(&iter);

    // Cleanup
    if (next_component) {
        icalcomponent_free(next_component);
    }
    icalcomponent_free(component);

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

    LLVMFuzzerTestOneInput_113(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
