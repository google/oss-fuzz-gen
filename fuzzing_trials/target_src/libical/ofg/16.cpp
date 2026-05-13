#include <cstdint> // Include for uint8_t
#include <cstddef> // Include for size_t
#include <cstring> // Include for memcpy
#include <cstdlib> // Include for malloc and free

extern "C" {
#include <libical/ical.h>
}

extern "C" int LLVMFuzzerTestOneInput_16(const uint8_t *data, size_t size) {
    // Check if the input size is sufficient to perform meaningful operations
    if (size == 0) {
        return 0;
    }

    // Initialize icalproperty and icalcomponent
    icalproperty *property = icalproperty_new(ICAL_ANY_PROPERTY);
    icalcomponent *component = icalcomponent_new(ICAL_NO_COMPONENT);

    if (property == NULL || component == NULL) {
        if (property != NULL) {
            icalproperty_free(property);
        }
        if (component != NULL) {
            icalcomponent_free(component);
        }
        return 0;
    }

    // Use the input data to set a property value
    char *value = (char *)malloc(size + 1);
    if (value == NULL) {
        icalproperty_free(property);
        icalcomponent_free(component);
        return 0;
    }
    memcpy(value, data, size);
    value[size] = '\0'; // Null-terminate the string

    // Set the value to the property
    icalproperty_set_value(property, icalvalue_new_string(value));

    // Call the function-under-test
    icalproperty_set_parent(property, component);

    // Perform additional operations to increase code coverage
    icalcomponent_add_property(component, property);

    // Clean up
    free(value);
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

    LLVMFuzzerTestOneInput_16(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
