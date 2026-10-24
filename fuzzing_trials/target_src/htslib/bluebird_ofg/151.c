#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

// Assume kstring_t is defined somewhere appropriately
typedef struct {
    size_t l, m;
    char *s;
} kstring_t;

// Function-under-test
char *haddextension(kstring_t *str, const char *ext, int flag, const char *suffix);

int LLVMFuzzerTestOneInput_151(const uint8_t *data, size_t size) {
    // Initialize kstring_t
    kstring_t kstr;
    kstr.l = size;
    kstr.m = size + 1;
    kstr.s = (char *)malloc(kstr.m);
    if (kstr.s == NULL) {
        return 0; // Exit if memory allocation fails
    }
    memcpy(kstr.s, data, size);
    kstr.s[size] = '\0'; // Null-terminate the string

    // Define non-NULL ext and suffix
    const char *ext = ".ext";
    const char *suffix = "_suffix";

    // Call the function-under-test
    char *result = haddextension(&kstr, ext, 1, suffix);

    // Free allocated memory for kstr.s
    free(kstr.s);

    // Check if haddextension allocates memory for the result and free it if necessary
    if (result != kstr.s && result != NULL) {
        free(result);
    }

    return 0;
}

#ifdef __cplusplus
}
#endif
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

    LLVMFuzzerTestOneInput_151(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
