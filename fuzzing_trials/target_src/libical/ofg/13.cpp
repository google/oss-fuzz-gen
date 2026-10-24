#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
    #include <libical/ical.h>
}

extern "C" int LLVMFuzzerTestOneInput_13(const uint8_t *data, size_t size) {
    // Initialize an icalcomponent from the input data
    icalcomponent *component = nullptr;
    if (size > 0) {
        // Create a string from the input data
        char *str = (char *)malloc(size + 1);
        if (str == nullptr) {
            return 0; // Memory allocation failed
        }
        memcpy(str, data, size);
        str[size] = '\0';

        // Parse the string into an icalcomponent
        component = icalparser_parse_string(str);
        free(str);
    }

    if (component != nullptr) {
        // Call the function-under-test
        icalproperty_method method = icalcomponent_get_method(component);

        // Clean up
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

    LLVMFuzzerTestOneInput_13(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
