#include <cstdint> // Include for uint8_t
#include <cstdlib> // Include for malloc and free
#include <cstring> // Include for memcpy

extern "C" {
    #include <libical/ical.h>
}

extern "C" int LLVMFuzzerTestOneInput_62(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient to create a valid icalcomponent
    if (size < 1) {
        return 0;
    }

    // Create a string from the input data to simulate a calendar component
    char *inputString = (char *)malloc(size + 1);
    if (inputString == NULL) {
        return 0;
    }
    memcpy(inputString, data, size);
    inputString[size] = '\0';

    // Parse the input string into an icalcomponent
    icalcomponent *component = icalparser_parse_string(inputString);
    if (component == NULL) {
        free(inputString);
        return 0;
    }

    // Create an iterator for the component
    icalcompiter iter = icalcomponent_begin_component(component, ICAL_ANY_COMPONENT);

    // Call the function-under-test
    icalcomponent *result = icalcompiter_deref(&iter);

    // Clean up
    free(inputString);
    icalcomponent_free(component);

    // Check if the result is not null to ensure the function is being tested
    if (result != NULL) {
        return 1;
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

    LLVMFuzzerTestOneInput_62(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
