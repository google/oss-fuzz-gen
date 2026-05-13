#include <cstddef>
#include <cstdint>
#include <cstring>

extern "C" {
    #include <libical/ical.h>
}

extern "C" int LLVMFuzzerTestOneInput_61(const uint8_t *data, size_t size) {
    // Ensure there is enough data to proceed
    if (size < 1) {
        return 0;
    }

    // Create a temporary string from the input data
    char *ical_string = new char[size + 1];
    memcpy(ical_string, data, size);
    ical_string[size] = '\0';

    // Initialize an icalcomponent from the string
    icalcomponent *component = icalparser_parse_string(ical_string);
    delete[] ical_string;

    if (component == nullptr) {
        return 0;
    }

    // Initialize an icalcompiter
    icalcompiter comp_iter = icalcomponent_begin_component(component, ICAL_ANY_COMPONENT);

    // Call the function-under-test
    icalcomponent *result = icalcompiter_deref(&comp_iter);

    // Clean up
    if (result != nullptr) {
        icalcomponent_free(result);
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

    LLVMFuzzerTestOneInput_61(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
