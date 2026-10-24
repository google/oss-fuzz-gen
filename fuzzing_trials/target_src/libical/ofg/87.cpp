#include <stdint.h>
#include <stddef.h>
#include <libical/ical.h>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput_87(const uint8_t *data, size_t size) {
    // Initialize an icalcomponent and icalproperty_method
    icalcomponent *component = icalcomponent_new(ICAL_VEVENT_COMPONENT);
    icalproperty_method method = ICAL_METHOD_NONE;

    // Ensure the data size is sufficient to extract a method
    if (size > 0) {
        // Use the first byte of data to determine the method
        // This is a simple mapping, assuming there are fewer than 256 methods
        method = static_cast<icalproperty_method>(data[0] % ICAL_METHOD_NONE);
    }

    // Call the function-under-test
    icalcomponent_set_method(component, method);

    // Add some properties to the component to increase code coverage
    if (size > 1) {
        // Create a property and set its value from the remaining data
        icalproperty *prop = icalproperty_new(ICAL_SUMMARY_PROPERTY);
        std::vector<char> summary(data + 1, data + size);
        summary.push_back('\0'); // Null-terminate the string
        icalproperty_set_summary(prop, summary.data());
        icalcomponent_add_property(component, prop);
    }

    // Clean up
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

    LLVMFuzzerTestOneInput_87(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
