#include <libical/ical.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

extern "C" int LLVMFuzzerTestOneInput_181(const uint8_t *data, size_t size) {
    // Check if the size is zero to prevent unnecessary processing
    if (size == 0) {
        return 0;
    }

    // Convert the input data to a null-terminated string
    char *inputString = (char *)malloc(size + 1);
    if (inputString == NULL) {
        return 0;
    }
    memcpy(inputString, data, size);
    inputString[size] = '\0';

    // Initialize icalcomponent and icalproperty
    icalcomponent *component = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);
    icalproperty *property = icalproperty_new_comment(inputString);

    // Check if component and property are successfully created
    if (component != NULL && property != NULL) {
        // Call the function-under-test
        icalcomponent_add_property(component, property);
    }

    // Clean up
    if (component != NULL) {
        icalcomponent_free(component);
    }

    // Free the allocated memory for the input string
    free(inputString);

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

    LLVMFuzzerTestOneInput_181(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
