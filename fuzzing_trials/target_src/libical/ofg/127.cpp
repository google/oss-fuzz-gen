#include <libical/ical.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
    #include <libical/ical.h>
}

extern "C" int LLVMFuzzerTestOneInput_127(const uint8_t *data, size_t size) {
    // Ensure the data is null-terminated for string operations
    char *inputStr = (char *)malloc(size + 1);
    if (!inputStr) {
        return 0; // Exit if memory allocation fails
    }
    memcpy(inputStr, data, size);
    inputStr[size] = '\0';

    // Parse the input data into an icalcomponent
    icalcomponent *component = icalparser_parse_string(inputStr);
    if (!component) {
        free(inputStr);
        return 0; // Exit if parsing fails
    }

    // Initialize the iterator
    icalproperty_kind kind = ICAL_ANY_PROPERTY;
    icalproperty *next_property = icalcomponent_get_first_property(component, kind);

    // Iterate through properties
    while (next_property != nullptr) {
        // Process the property (for example, print or modify it)
        next_property = icalcomponent_get_next_property(component, kind);
    }

    // Clean up
    icalcomponent_free(component);
    free(inputStr);

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

    LLVMFuzzerTestOneInput_127(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
