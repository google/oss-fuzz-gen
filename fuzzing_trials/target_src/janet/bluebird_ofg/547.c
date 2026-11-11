#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Function signature to be fuzzed
void janet_dynprintf(const char *prefix, FILE *file, const char *format, void *data);

int LLVMFuzzerTestOneInput_547(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient to extract meaningful data
    if (size < 4) {
        return 0;
    }

    // Split the input data into parts for different parameters
    size_t prefix_len = size / 4;
    size_t format_len = size / 4;
    size_t data_len = size - (prefix_len + format_len);

    // Allocate memory for the prefix and format strings, and a buffer for the data
    char *prefix = (char *)malloc(prefix_len + 1);
    char *format = (char *)malloc(format_len + 1);
    char *data_buffer = (char *)malloc(data_len + 1); // Ensure null-termination

    if (!prefix || !format || !data_buffer) {
        free(prefix);
        free(format);
        free(data_buffer);
        return 0;
    }

    // Copy data into the allocated memory and null-terminate the strings
    memcpy(prefix, data, prefix_len);
    prefix[prefix_len] = '\0';

    memcpy(format, data + prefix_len, format_len);
    format[format_len] = '\0';

    memcpy(data_buffer, data + prefix_len + format_len, data_len);
    data_buffer[data_len] = '\0'; // Null-terminate to prevent buffer overflow

    // Open a temporary file to pass as the FILE* parameter
    FILE *temp_file = tmpfile();
    if (!temp_file) {
        free(prefix);
        free(format);
        free(data_buffer);
        return 0;
    }

    // Ensure the format string is safe to use
    if (strchr(format, '%') == NULL || strlen(format) == 0) {
        // Call the function-under-test
        janet_dynprintf(prefix, temp_file, format, data_buffer);
    }

    // Clean up
    fclose(temp_file);
    free(prefix);
    free(format);
    free(data_buffer);

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

    LLVMFuzzerTestOneInput_547(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
