#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>  // Include for FILE and tmpfile

extern "C" {
    #include <magic.h>
    const char * magic_descriptor(struct magic_set *, int);
}

extern "C" int LLVMFuzzerTestOneInput_42(const uint8_t *data, size_t size) {
    // Initialize a magic_set structure
    struct magic_set *magic = magic_open(MAGIC_NONE);
    if (magic == NULL) {
        return 0;
    }

    // Load default magic database
    if (magic_load(magic, NULL) != 0) {
        magic_close(magic);
        return 0;
    }

    // Create a temporary file
    FILE *temp_file = tmpfile();
    if (temp_file == NULL) {
        magic_close(magic);
        return 0;
    }

    // Write the input data to the temporary file
    if (fwrite(data, 1, size, temp_file) != size) {
        fclose(temp_file);
        magic_close(magic);
        return 0;
    }

    // Rewind the file to the beginning
    rewind(temp_file);

    // Get the file descriptor
    int descriptor = fileno(temp_file);

    // Call the function-under-test
    const char *result = magic_descriptor(magic, descriptor);

    // Clean up
    fclose(temp_file);
    magic_close(magic);

    // Check result to ensure function is being exercised
    if (result == NULL) {
        return 0;
    }

    // Print the result to ensure the function is being exercised
    printf("Magic descriptor result: %s\n", result);

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

    LLVMFuzzerTestOneInput_42(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
