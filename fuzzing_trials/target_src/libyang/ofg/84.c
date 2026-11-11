#include <stdint.h>
#include <time.h>

extern int ly_time_tz_offset_at(time_t);

int LLVMFuzzerTestOneInput_84(const uint8_t *data, size_t size) {
    // Ensure there is enough data to form a time_t value
    if (size < sizeof(time_t)) {
        return 0;
    }

    // Extract a time_t value from the input data
    time_t input_time;
    memcpy(&input_time, data, sizeof(time_t));

    // Call the function under test
    int offset = ly_time_tz_offset_at(input_time);

    // Use the result in some way to avoid compiler optimizations
    (void)offset;

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

    LLVMFuzzerTestOneInput_84(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
