#include <stdint.h>
#include <time.h>

// Assuming ly_time_tz_offset_at is defined elsewhere
int ly_time_tz_offset_at(time_t);

int LLVMFuzzerTestOneInput_83(const uint8_t *data, size_t size) {
    // Declare and initialize a time_t variable
    time_t input_time;

    // Ensure there's enough data to fill a time_t variable
    if (size < sizeof(time_t)) {
        return 0;
    }

    // Copy data into the time_t variable
    memcpy(&input_time, data, sizeof(time_t));

    // Call the function-under-test
    ly_time_tz_offset_at(input_time);

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

    LLVMFuzzerTestOneInput_83(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
