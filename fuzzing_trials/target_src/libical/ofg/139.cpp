#include <libical/ical.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>  // For malloc and free
#include <string.h>  // For memcpy

extern "C" {
    // Include necessary C headers and functions here
}

extern "C" int LLVMFuzzerTestOneInput_139(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient to create a valid string
    if (size < 1) {
        return 0;
    }

    // Create a null-terminated string from the input data
    char *ical_string = (char *)malloc(size + 1);
    if (!ical_string) {
        return 0;
    }
    memcpy(ical_string, data, size);
    ical_string[size] = '\0';

    // Parse the string into an icalcomponent
    icalcomponent *comp = icalparser_parse_string(ical_string);

    // Ensure the component is not NULL
    if (comp != NULL) {
        // Use a valid icalcomponent_kind for testing
        icalcomponent_kind kind = ICAL_VEVENT_COMPONENT;

        // Call the function-under-test
        int count = icalcomponent_count_components(comp, kind);

        // Clean up
        icalcomponent_free(comp);
    }

    free(ical_string);

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

    LLVMFuzzerTestOneInput_139(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
