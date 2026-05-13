#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>  // Include for memcpy

extern "C" {
    #include <libical/ical.h>
}

extern "C" int LLVMFuzzerTestOneInput_123(const uint8_t *data, size_t size) {
    // Ensure size is sufficient to create a valid icalcomponent
    if (size == 0) {
        return 0;
    }

    // Create a temporary string from the input data
    char *ical_str = (char *)malloc(size + 1);
    if (!ical_str) {
        return 0;
    }
    memcpy(ical_str, data, size);
    ical_str[size] = '\0'; // Null-terminate the string

    // Parse the string into an icalcomponent
    icalcomponent *component = icalparser_parse_string(ical_str);
    free(ical_str);

    if (component == NULL) {
        return 0;
    }

    // Clone the component
    icalcomponent *cloned_component = icalcomponent_clone(component);

    // Clean up
    icalcomponent_free(component);
    if (cloned_component != NULL) {
        icalcomponent_free(cloned_component);
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

    LLVMFuzzerTestOneInput_123(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
