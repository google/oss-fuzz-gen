#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>

// Function-under-test
void janet_panicf(const char *fmt, void *arg);

// Signal handler to catch abort signals
void handle_abort_224(int sig) {
    fprintf(stderr, "Caught signal %d\n", sig);
    exit(1);
}

int LLVMFuzzerTestOneInput_224(const uint8_t *data, size_t size) {
    // Ensure the data is large enough to contain a null-terminated string and an argument
    if (size < 3) {
        return 0;
    }

    // Set up signal handler for SIGABRT
    signal(SIGABRT, handle_abort_224);

    // Allocate a buffer for the string and ensure it's null-terminated
    char *fmt = (char *)malloc(size + 1);
    if (!fmt) {
        return 0;
    }
    memcpy(fmt, data, size);
    fmt[size] = '\0';

    // Use the first few bytes of data to create a more complex argument
    int dummy_value = (data[0] << 8) | data[1];  // Combine first two bytes for a more varied argument
    void *arg = &dummy_value;

    // Ensure the format string is not empty and contains some format specifiers
    if (fmt[0] == '\0' || strchr(fmt, '%') == NULL) {
        free(fmt);
        return 0;
    }

    // Call the function-under-test
    janet_panicf(fmt, arg);

    // Clean up
    free(fmt);

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

    LLVMFuzzerTestOneInput_224(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
