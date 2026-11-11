#include <cstdint>
#include <cstring>
#include <cstdlib>

extern "C" {
    #include <libical/icalcomponent.h>
    #include <libical/icaltimezone.h>
}

extern "C" int LLVMFuzzerTestOneInput_75(const uint8_t *data, size_t size) {
    // Ensure the data size is large enough to create a valid string
    if (size < 1) return 0;

    // Initialize an icalcomponent
    icalcomponent *component = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);

    // Create a null-terminated string from the input data
    char *timezone_id = (char *)malloc(size + 1);
    memcpy(timezone_id, data, size);
    timezone_id[size] = '\0';

    // Call the function-under-test
    icaltimezone *timezone = icalcomponent_get_timezone(component, timezone_id);

    // Clean up
    free(timezone_id);
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

    LLVMFuzzerTestOneInput_75(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
