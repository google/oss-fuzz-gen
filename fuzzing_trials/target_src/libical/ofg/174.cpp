#include <stdint.h>
#include <stdlib.h>
#include <libical/ical.h>

extern "C" {
    #include <string.h> // Include the string.h library for memcpy
}

extern "C" int LLVMFuzzerTestOneInput_174(const uint8_t *data, size_t size) {
    // Allocate memory for the icalcomponent
    icalcomponent *component = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);

    // Ensure the component is not NULL
    if (component == NULL) {
        return 0;
    }

    // Create a temporary buffer to hold the input data
    char *temp_buffer = (char *)malloc(size + 1);
    if (temp_buffer == NULL) {
        icalcomponent_free(component);
        return 0;
    }

    // Copy the input data to the temporary buffer and null-terminate it
    memcpy(temp_buffer, data, size);
    temp_buffer[size] = '\0';

    // Parse the input data into the icalcomponent
    icalcomponent *parsed_component = icalparser_parse_string(temp_buffer);

    // Free the temporary buffer
    free(temp_buffer);

    // If parsing was successful, check restrictions
    if (parsed_component != NULL) {
        // Call the function-under-test
        bool result = icalcomponent_check_restrictions(parsed_component);

        // Free the parsed component
        icalcomponent_free(parsed_component);
    }

    // Free the original component
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

    LLVMFuzzerTestOneInput_174(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
