#include <stdint.h>
#include <stdlib.h>
#include <string.h> // Include this for memcpy

extern "C" {
    #include <libical/ical.h>
}

extern "C" int LLVMFuzzerTestOneInput_104(const uint8_t *data, size_t size) {
    // Initialize the icalcomponent
    icalcomponent *component = icalcomponent_new(ICAL_VEVENT_COMPONENT);

    // Create a buffer with the input data
    char *inputData = (char *)malloc(size + 1);
    if (inputData == NULL) {
        icalcomponent_free(component);
        return 0;
    }
    memcpy(inputData, data, size);
    inputData[size] = '\0'; // Ensure null-termination

    // Create a temporary icalproperty to set a DTSTART
    icalproperty *dtstart_prop = icalproperty_new_from_string(inputData);
    if (dtstart_prop != NULL) {
        icalcomponent_add_property(component, dtstart_prop);
    }

    // Call the function-under-test
    struct icaltimetype dtstart = icalcomponent_get_dtstart(component);

    // Clean up
    icalcomponent_free(component);
    free(inputData);

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

    LLVMFuzzerTestOneInput_104(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
