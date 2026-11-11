#include <stdint.h>
#include <stddef.h>
#include <janet.h>

// Function-under-test
void janet_signalv(JanetSignal signal, Janet value);

int LLVMFuzzerTestOneInput_352(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract a JanetSignal and a Janet
    if (size < sizeof(JanetSignal) + sizeof(Janet)) {
        return 0;
    }

    // Initialize Janet runtime
    janet_init();

    // Extract JanetSignal from data
    JanetSignal signal = *(const JanetSignal *)data;

    // Extract Janet from data
    const Janet *janetData = (const Janet *)(data + sizeof(JanetSignal));
    Janet value = *janetData;

    // Call the function-under-test
    janet_signalv(signal, value);

    // Clean up Janet runtime
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

    LLVMFuzzerTestOneInput_352(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
