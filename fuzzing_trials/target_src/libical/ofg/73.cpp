#include <libical/ical.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h> // For malloc and free
#include <string.h> // For memcpy

extern "C" {
    #include <libical/ical.h>
}

extern "C" int LLVMFuzzerTestOneInput_73(const uint8_t *data, size_t size) {
    // Ensure the data is large enough to form a valid icalcomponent
    if (size < 1) {
        return 0;
    }

    // Create a temporary buffer to hold the data, ensuring null termination
    char *buffer = (char *)malloc(size + 1);
    if (buffer == NULL) {
        return 0;
    }
    memcpy(buffer, data, size);
    buffer[size] = '\0';

    // Parse the data into an icalcomponent
    icalcomponent *component = icalparser_parse_string(buffer);
    free(buffer);

    if (component == NULL) {
        return 0;
    }

    // Define a valid icalcomponent_kind, using a basic kind for fuzzing
    icalcomponent_kind kind = ICAL_VEVENT_COMPONENT;

    // Call the function-under-test
    icalcompiter iter = icalcomponent_end_component(component, kind);

    // Clean up
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

    LLVMFuzzerTestOneInput_73(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
