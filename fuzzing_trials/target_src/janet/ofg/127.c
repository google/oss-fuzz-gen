#include <stdint.h>
#include <stddef.h>
#include <string.h> // Include for memcpy
#include <janet.h>

// Define a dummy JanetAbstractType for testing
static const JanetAbstractType dummy_abstract_type = {
    "dummy_type",
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

int LLVMFuzzerTestOneInput_127(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract meaningful values
    if (size < sizeof(Janet) + 2 * sizeof(int32_t)) {
        return 0;
    }

    // Initialize the Janet environment
    janet_init();

    // Extract a Janet value from the data
    Janet janet_value;
    memcpy(&janet_value, data, sizeof(Janet));
    data += sizeof(Janet);
    size -= sizeof(Janet);

    // Extract two int32_t values from the data
    int32_t index1, index2;
    memcpy(&index1, data, sizeof(int32_t));
    data += sizeof(int32_t);
    size -= sizeof(int32_t);

    memcpy(&index2, data, sizeof(int32_t));
    data += sizeof(int32_t);
    size -= sizeof(int32_t);

    // Ensure janet_value is a valid Janet abstract type
    if (!janet_checktype(janet_value, JANET_ABSTRACT)) {
        janet_deinit();
        return 0;
    }

    // Call the function-under-test
    JanetAbstract result = janet_optabstract(&janet_value, index1, index2, &dummy_abstract_type, NULL);

    // Clean up the Janet environment
    janet_deinit();

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

    LLVMFuzzerTestOneInput_127(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
