#include <cstdint>  // Include for uint8_t
#include <cstddef>  // Include for size_t
#include <cstring>  // Include for memcpy

extern "C" {
#include <libical/ical.h>
}

extern "C" int LLVMFuzzerTestOneInput_76(const uint8_t *data, size_t size) {
    // Ensure the input data is not null and has a reasonable size
    if (data == nullptr || size == 0) {
        return 0;
    }

    // Initialize an icalcomponent and icalproperty_kind
    icalcomponent *component = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);
    if (component == nullptr) {
        return 0;
    }

    icalproperty_kind kind = ICAL_SUMMARY_PROPERTY;  // Use a specific property kind

    // Use the input data to create a summary string
    char summary[256] = "Test Summary";
    size_t copy_size = size < 255 ? size : 255;  // Ensure null-termination
    memcpy(summary, data, copy_size);
    summary[copy_size] = '\0';

    // Add a property to the component using the input data as the summary
    icalproperty *property = icalproperty_new_summary(summary);
    if (property == nullptr) {
        icalcomponent_free(component);
        return 0;
    }
    icalcomponent_add_property(component, property);

    // Call the function-under-test
    icalproperty *result = icalcomponent_get_first_property(component, kind);

    // Check if the result is not null to ensure the function is tested effectively
    if (result != nullptr) {
        // Extract the summary from the result property to ensure the function is being tested effectively
        const char *extracted_summary = icalproperty_get_summary(result);
        if (extracted_summary != nullptr) {
            // Perform additional checks or operations as needed
            // For example, compare extracted_summary with the original summary
            if (strcmp(extracted_summary, summary) != 0) {
                // Log or handle the mismatch if necessary
            }
        }
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

    LLVMFuzzerTestOneInput_76(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
