#include <stdint.h>
#include <stdbool.h>
#include <libical/ical.h>

extern "C" int LLVMFuzzerTestOneInput_4(const uint8_t *data, size_t size) {
    // Ensure there is enough data to read an icalcomponent_kind value
    if (size < sizeof(icalcomponent_kind)) {
        return 0;
    }

    // Cast the input data to icalcomponent_kind
    icalcomponent_kind kind = *(const icalcomponent_kind *)data;

    // Call the function-under-test
    bool is_valid = icalcomponent_kind_is_valid(kind);

    // Use the result to prevent the compiler from optimizing away the call
    if (is_valid) {
        // Do something trivial
        volatile int dummy = 0;
        (void)dummy;
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

    LLVMFuzzerTestOneInput_4(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
