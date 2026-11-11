#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>  // Include for unlink, write, and close
#include <magic.h>

extern "C" {
    const char * magic_buffer(struct magic_set *, const void *, size_t);
}

extern "C" int LLVMFuzzerTestOneInput_16(const uint8_t *data, size_t size) {
    // Initialize a magic_set structure
    struct magic_set *ms = magic_open(MAGIC_NONE);
    if (ms == NULL) {
        return 0;
    }

    // Load the default magic database
    if (magic_load(ms, NULL) != 0) {
        magic_close(ms);
        return 0;
    }

    // Ensure that the data is not null and has a reasonable size
    if (data == NULL || size == 0) {
        magic_close(ms);
        return 0;
    }

    // Call the function-under-test directly on the buffer
    const char *result = magic_buffer(ms, data, size);

    // Check if result is NULL and handle it
    if (result == NULL) {
        // If result is NULL, it means the function didn't recognize the file type
        // This is a valid case, but we should ensure that the function is being tested
        // by printing a message or logging for debugging purposes
        fprintf(stderr, "Magic buffer returned NULL\n");
    } else {
        // Print the result (optional, for debugging purposes)
        fprintf(stderr, "Magic buffer: %s\n", result);
    }

    // Clean up
    magic_close(ms);

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

    LLVMFuzzerTestOneInput_16(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
