#include <libical/ical.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h> // For malloc and free
#include <string.h> // For memcpy

extern "C" {
    // Include necessary C headers, source files, functions, and code here.
    #include <libical/ical.h>
}

extern "C" int LLVMFuzzerTestOneInput_79(const uint8_t *data, size_t size) {
    // Ensure the data is not empty
    if (size == 0) {
        return 0;
    }

    // Create a temporary string from the input data
    char *input = (char *)malloc(size + 1);
    if (input == NULL) {
        return 0;
    }
    memcpy(input, data, size);
    input[size] = '\0';

    // Parse the input data into an icalcomponent
    icalcomponent *component = icalparser_parse_string(input);
    free(input);

    // If parsing was successful, proceed with fuzzing
    if (component != NULL) {
        // Iterate over a few icalproperty_kind values
        for (int kind = ICAL_ANY_PROPERTY; kind <= ICAL_X_PROPERTY; ++kind) {
            // Call the function-under-test
            int count = icalcomponent_count_properties(component, (icalproperty_kind)kind);

            // Use the result to prevent compiler optimizations
            if (count < 0) {
                break;
            }
        }

        // Free the icalcomponent
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

    LLVMFuzzerTestOneInput_79(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
