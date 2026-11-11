#include <stdint.h>
#include <stddef.h>
#include <libical/ical.h>

extern "C" int LLVMFuzzerTestOneInput_67(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    icalcomponent_kind kind;

    // Ensure the size is sufficient to extract a valid icalcomponent_kind
    if (size < sizeof(icalcomponent_kind)) {
        return 0;
    }

    // Cast the data to icalcomponent_kind
    kind = static_cast<icalcomponent_kind>(data[0]);

    // Call the function-under-test
    const char *result = icalcomponent_kind_to_string(kind);

    // Use the result to avoid compiler optimizations removing the call
    if (result != NULL) {
        // Do something with the result, like printing it (in a real fuzzing scenario, this might not be necessary)
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

    LLVMFuzzerTestOneInput_67(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
