#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

extern "C" {
    #include <libical/ical.h>
}

extern "C" int LLVMFuzzerTestOneInput_80(const uint8_t *data, size_t size) {
    // Ensure there's enough data for a null-terminated string
    if (size < 1) {
        return 0;
    }

    // Create an icalcomponent
    icalcomponent *component = icalcomponent_new(ICAL_VEVENT_COMPONENT);
    if (component == NULL) {
        return 0;
    }

    // Create a null-terminated string from the input data
    char *x_name = (char *)malloc(size + 1);
    if (x_name == NULL) {
        icalcomponent_free(component);
        return 0;
    }
    memcpy(x_name, data, size);
    x_name[size] = '\0';

    // Call the function-under-test
    icalcomponent_set_x_name(component, x_name);

    // To increase code coverage, retrieve the x-name and ensure it matches the input
    const char *retrieved_x_name = icalcomponent_get_x_name(component);
    if (retrieved_x_name != NULL) {
        // Compare the set and retrieved x-name
        if (strcmp(x_name, retrieved_x_name) != 0) {
            // Handle mismatch if necessary
        }
    }

    // Clean up
    icalcomponent_free(component);
    free(x_name);

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

    LLVMFuzzerTestOneInput_80(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
