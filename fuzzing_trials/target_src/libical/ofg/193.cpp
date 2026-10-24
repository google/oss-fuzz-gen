#include <libical/ical.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_193(const uint8_t *data, size_t size) {
    // Convert the input data to a string
    char *ical_string = static_cast<char *>(malloc(size + 1));
    if (!ical_string) {
        return 0;
    }
    memcpy(ical_string, data, size);
    ical_string[size] = '\0';

    // Parse the string into an icalcomponent
    icalcomponent *component = icalparser_parse_string(ical_string);
    free(ical_string);

    if (component == NULL) {
        return 0;
    }

    // Initialize a icalcompiter
    icalcompiter iter = icalcomponent_begin_component(component, ICAL_ANY_COMPONENT);

    // Call the function-under-test
    icalcomponent *prior_component = icalcompiter_prior(&iter);

    // Clean up
    if (prior_component != NULL) {
        icalcomponent_free(prior_component);
    }
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

    LLVMFuzzerTestOneInput_193(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
