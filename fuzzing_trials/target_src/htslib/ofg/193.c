#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Function-under-test
char *stringify_argv(int argc, char **argv);

int LLVMFuzzerTestOneInput_193(const uint8_t *data, size_t size) {
    // Ensure size is at least enough to form one argument
    if (size < 1) return 0;

    // Allocate memory for argv array
    int argc = size > 10 ? 10 : size; // Limit argc to a maximum of 10 for simplicity
    char **argv = (char **)malloc(argc * sizeof(char *));
    if (argv == NULL) return 0;

    // Allocate memory for each argument and copy data
    size_t arg_length = size / argc;
    for (int i = 0; i < argc; i++) {
        argv[i] = (char *)malloc(arg_length + 1);
        if (argv[i] == NULL) {
            for (int j = 0; j < i; j++) {
                free(argv[j]);
            }
            free(argv);
            return 0;
        }
        memcpy(argv[i], data + i * arg_length, arg_length);
        argv[i][arg_length] = '\0'; // Null-terminate each argument
    }

    // Call the function-under-test
    char *result = stringify_argv(argc, argv);

    // Clean up
    for (int i = 0; i < argc; i++) {
        free(argv[i]);
    }
    free(argv);
    free(result);

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

    LLVMFuzzerTestOneInput_193(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
