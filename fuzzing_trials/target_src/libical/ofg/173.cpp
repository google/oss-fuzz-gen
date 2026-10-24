#include <stdint.h>
#include <stdlib.h>
#include <libical/ical.h>

extern "C" {
    #include <string.h> // Include the string.h library for memcpy
}

extern "C" int LLVMFuzzerTestOneInput_173(const uint8_t *data, size_t size) {
    // Ensure the data is not empty
    if (size == 0) {
        return 0;
    }

    // Create an icalcomponent from the input data
    char *str_data = (char *)malloc(size + 1);
    if (!str_data) {
        return 0;
    }

    // Copy the data into a null-terminated string
    memcpy(str_data, data, size);
    str_data[size] = '\0';

    // Parse the string into an icalcomponent
    icalcomponent *component = icalparser_parse_string(str_data);

    // Free the string data
    free(str_data);

    // If parsing was successful, check the restrictions
    if (component != NULL) {
        bool result = icalcomponent_check_restrictions(component);

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

    LLVMFuzzerTestOneInput_173(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
