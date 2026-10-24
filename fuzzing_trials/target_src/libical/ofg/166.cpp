#include <stdint.h>
#include <stddef.h>
#include <string> // Include the string header for std::string

extern "C" {
    #include <libical/ical.h>
}

extern "C" int LLVMFuzzerTestOneInput_166(const uint8_t *data, size_t size) {
    // Convert the input data to a string, assuming it is a valid UTF-8 sequence
    std::string input(reinterpret_cast<const char*>(data), size);

    // Parse the input data as an iCalendar component
    icalcomponent *component = icalparser_parse_string(input.c_str());

    // Clean up the created component to avoid memory leaks
    if (component != NULL) {
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

    LLVMFuzzerTestOneInput_166(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
