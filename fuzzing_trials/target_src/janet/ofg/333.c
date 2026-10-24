#include <stdint.h>
#include <stddef.h>
#include <janet.h>

// Define a dummy JanetAbstractType for testing purposes
static const JanetAbstractType dummyAbstractType = {
    "dummyType",
    NULL, // No function pointers for simplicity
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

int LLVMFuzzerTestOneInput_333(const uint8_t *data, size_t size) {
    // Ensure the data is large enough to be used as a Janet value
    if (size < sizeof(Janet)) {
        return 0;
    }

    // Cast the data to a Janet value
    Janet janetValue = *((Janet *)data);

    // Call the function-under-test
    JanetAbstract result = janet_checkabstract(janetValue, &dummyAbstractType);

    // Use the result in some way to avoid compiler optimizations
    if (result != NULL) {
        // For example, we can cast it to a void pointer and do nothing
        (void)(result);
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_333(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
