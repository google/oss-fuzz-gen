#include <sys/stat.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Assume the function is declared in some header file included here
// int hfile_list_schemes(const char *, const char **, int *);

extern int hfile_list_schemes(const char *, const char **, int *);

int LLVMFuzzerTestOneInput_70(const uint8_t *data, size_t size) {
    // Define and initialize the parameters for hfile_list_schemes
    const char *input_string = NULL;
    const char *schemes[10] = { "http", "https", "ftp", "file", "s3", "gs", "hdfs", "webhdfs", "sftp", "ftps" };
    int count = 0;

    // Ensure the data size is sufficient to create a valid string
    if (size > 0) {
        // Allocate memory for the input string
        input_string = (const char *)malloc(size + 1);
        if (input_string == NULL) {
            return 0; // Exit if memory allocation fails
        }

        // Copy data into the input string and null-terminate it
        memcpy((char *)input_string, data, size);
        ((char *)input_string)[size] = '\0'; // Ensure null-termination
    }

    // Call the function-under-test
    hfile_list_schemes(input_string, schemes, &count);

    // Free the allocated memory
    if (input_string != NULL) {
        free((char *)input_string);
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

    LLVMFuzzerTestOneInput_70(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
