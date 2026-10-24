#include <libical/ical.h>
#include <cstddef>
#include <cstdint>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_129(const uint8_t *data, size_t size) {
    // Ensure there is enough data to create a valid icalcomponent
    if (size == 0) {
        return 0;
    }

    // Create a temporary buffer to hold the data
    char *buffer = new char[size + 1];
    memcpy(buffer, data, size);
    buffer[size] = '\0';  // Null-terminate the buffer to make it a valid string

    // Parse the buffer into an icalcomponent
    icalcomponent *component = icalparser_parse_string(buffer);

    // If parsing was successful, call the function-under-test
    if (component != nullptr) {
        icalproperty *property = icalcomponent_get_current_property(component);
        // Normally you would do something with the property, but for fuzzing, just ensure the function is called
    }

    // Clean up
    if (component != nullptr) {
        icalcomponent_free(component);
    }
    delete[] buffer;

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

    LLVMFuzzerTestOneInput_129(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
