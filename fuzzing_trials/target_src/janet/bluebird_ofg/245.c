#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "janet.h"

extern void janet_cfuns(JanetTable *env, const char *name, const JanetReg *cfuns);

int LLVMFuzzerTestOneInput_245(const uint8_t *data, size_t size) {
    // Initialize Janet runtime
    janet_init();

    // Create a JanetTable
    JanetTable *env = janet_table(10);

    // Ensure the size is sufficient for a null-terminated string
    if (size < 1) {
        janet_deinit();
        return 0;
    }

    // Allocate memory for the name and ensure it's null-terminated
    char *name = (char *)malloc(size + 1);
    if (!name) {
        janet_deinit();
        return 0;
    }
    memcpy(name, data, size);
    name[size] = '\0';

    // Create a dummy JanetReg array
    JanetReg cfuns[] = {
        {"dummy_function", NULL, NULL},
        {NULL, NULL, NULL} // Sentinel value
    };

    // Call the function-under-test
    janet_cfuns(env, name, cfuns);

    // Clean up
    free(name);
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

    LLVMFuzzerTestOneInput_245(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
