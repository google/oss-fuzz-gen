#include <libical/ical.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_86(const uint8_t *data, size_t size) {
    // Ensure the size is large enough to create a valid icalcomponent
    if (size < 1) {
        return 0;
    }

    // Allocate memory for the icalcomponent string
    char *ical_str = static_cast<char *>(malloc(size + 1));
    if (ical_str == nullptr) {
        return 0;
    }

    // Copy the data into the icalcomponent string and null-terminate it
    memcpy(ical_str, data, size);
    ical_str[size] = '\0';

    // Convert the string to an icalcomponent
    icalcomponent *comp = icalparser_parse_string(ical_str);

    // Free the allocated string memory
    free(ical_str);

    // If the component is successfully created, call the function-under-test
    if (comp != nullptr) {
        struct icaltimetype dtstamp = icalcomponent_get_dtstamp(comp);

        // Clean up the icalcomponent
        icalcomponent_free(comp);
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

    LLVMFuzzerTestOneInput_86(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
