#include <libical/ical.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// Ensure C linkage for the function-under-test and libical functions
extern "C" {
    icalcomponent *icalcomponent_get_inner(icalcomponent *);
    icalcomponent *icalparser_parse_string(const char *str);
    icalparser *icalparser_new();
    void icalparser_free(icalparser *);
    void icalcomponent_free(icalcomponent *);
}

extern "C" int LLVMFuzzerTestOneInput_111(const uint8_t *data, size_t size) {
    // Initialize libical
    icalcomponent *component = nullptr;
    icalcomponent *inner_component = nullptr;
    icalparser *parser = nullptr;

    // Create a parser
    parser = icalparser_new();
    if (parser == nullptr) {
        return 0;
    }

    // Create a string from the input data
    char *input_data = (char *)malloc(size + 1);
    if (input_data == nullptr) {
        icalparser_free(parser);
        return 0;
    }
    memcpy(input_data, data, size);
    input_data[size] = '\0';

    // Parse the input data into an icalcomponent
    component = icalparser_parse_string(input_data);
    if (component == nullptr) {
        free(input_data);
        icalparser_free(parser);
        return 0;
    }

    // Call the function-under-test
    inner_component = icalcomponent_get_inner(component);

    // Clean up
    free(input_data);
    icalparser_free(parser);
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

    LLVMFuzzerTestOneInput_111(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
