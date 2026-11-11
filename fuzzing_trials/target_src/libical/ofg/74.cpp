#include <libical/ical.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_74(const uint8_t *data, size_t size) {
    // Initialize the variables
    icalcomponent *component = nullptr;
    char *timezone_id = nullptr;

    // Ensure the size is large enough to split into component and timezone_id
    if (size < 2) {
        return 0;
    }

    // Allocate memory for timezone_id and ensure it's null-terminated
    size_t timezone_id_size = size / 2;
    timezone_id = static_cast<char *>(malloc(timezone_id_size + 1));
    if (timezone_id == nullptr) {
        return 0;
    }
    memcpy(timezone_id, data, timezone_id_size);
    timezone_id[timezone_id_size] = '\0';

    // Create a dummy component for fuzzing
    component = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);
    if (component == nullptr) {
        free(timezone_id);
        return 0;
    }

    // Call the function-under-test
    icaltimezone *timezone = icalcomponent_get_timezone(component, timezone_id);

    // Clean up
    icalcomponent_free(component);
    free(timezone_id);

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

    LLVMFuzzerTestOneInput_74(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
