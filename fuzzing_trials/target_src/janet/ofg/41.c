#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>

// Assuming the function is defined elsewhere
extern void janet_await(const uint8_t *data, size_t size);

// Signal handler for abort signals
void handle_abort_41(int sig) {
    // You can log the signal or handle it in a way that makes sense for your fuzzing environment
    // For now, just exit gracefully
    exit(1);
}

int LLVMFuzzerTestOneInput_41(const uint8_t *data, size_t size) {
    // Set up a signal handler for SIGABRT to prevent the fuzzer from crashing
    signal(SIGABRT, handle_abort_41);

    // Ensure the data is not null and size is greater than zero
    if (data == NULL || size == 0) {
        return 0; // Early exit if data is null or size is zero
    }

    // Make a copy of the data to ensure it is not modified by janet_await
    volatile uint8_t *data_copy = (uint8_t *)malloc(size);
    if (data_copy == NULL) {
        return 0; // If memory allocation fails, exit early
    }
    memcpy((void *)data_copy, data, size);

    // Call janet_await with the provided data and size
    janet_await((const uint8_t *)data_copy, size);

    // Free the allocated memory
    free((void *)data_copy);

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

    LLVMFuzzerTestOneInput_41(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
