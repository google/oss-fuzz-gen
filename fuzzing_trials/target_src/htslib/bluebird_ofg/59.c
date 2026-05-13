#include <sys/stat.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Function-under-test
char *stringify_argv(int argc, char **argv);

int LLVMFuzzerTestOneInput_59(const uint8_t *data, size_t size) {
    // Ensure size is sufficient for at least one argument
    if (size < 2) {
        return 0;
    }

    // Allocate memory for the argv array
    char **argv = (char **)malloc(size * sizeof(char *));
    if (argv == NULL) {
        return 0;
    }

    // Split the input data into separate strings for argv
    size_t arg_index = 0;
    size_t start = 0;
    for (size_t i = 0; i < size; i++) {
        if (data[i] == '\0' || i == size - 1) {
            size_t length = i - start + 1;
            argv[arg_index] = (char *)malloc(length);
            if (argv[arg_index] == NULL) {
                // Free previously allocated memory if malloc fails
                for (size_t j = 0; j < arg_index; j++) {
                    free(argv[j]);
                }
                free(argv);
                return 0;
            }
            memcpy(argv[arg_index], &data[start], length - 1);
            argv[arg_index][length - 1] = '\0'; // Ensure null-termination
            arg_index++;
            start = i + 1;
        }
    }

    // Ensure there is at least one argument
    if (arg_index == 0) {
        argv[arg_index] = (char *)malloc(1);
        if (argv[arg_index] != NULL) {
            argv[arg_index][0] = '\0';
            arg_index++;
        }
    }

    // Call the function-under-test
    char *result = stringify_argv((int)arg_index, argv);

    // Free the result if it's dynamically allocated
    if (result != NULL) {
        free(result);
    }

    // Free the allocated memory for argv
    for (size_t i = 0; i < arg_index; i++) {
        free(argv[i]);
    }
    free(argv);

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

    LLVMFuzzerTestOneInput_59(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
