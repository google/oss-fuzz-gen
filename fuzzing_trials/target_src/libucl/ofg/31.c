#include <stdint.h>
#include <stdlib.h>
#include <ucl.h>

// Define a dummy append character function for ucl_emitter_functions
static int dummy_append_character(unsigned char c, size_t nchars, void *ud) {
    (void)c; // Unused parameter
    (void)nchars; // Unused parameter
    (void)ud; // Unused parameter
    return 0;
}

// Define a dummy append length function for ucl_emitter_functions
static int dummy_append_len(const unsigned char *str, size_t len, void *ud) {
    (void)str; // Unused parameter
    (void)len; // Unused parameter
    (void)ud; // Unused parameter
    return 0;
}

// Define a dummy append integer function for ucl_emitter_functions
static int dummy_append_int(int64_t elt, void *ud) {
    (void)elt; // Unused parameter
    (void)ud; // Unused parameter
    return 0;
}

// Define a dummy append double function for ucl_emitter_functions
static int dummy_append_double(double elt, void *ud) {
    (void)elt; // Unused parameter
    (void)ud; // Unused parameter
    return 0;
}

// Define a dummy free function for ucl_emitter_functions
static void dummy_free_func(void *ud) {
    (void)ud; // Unused parameter
}

int LLVMFuzzerTestOneInput_31(const uint8_t *data, size_t size) {
    struct ucl_emitter_functions *emitter_funcs;

    // Allocate memory for ucl_emitter_functions
    emitter_funcs = (struct ucl_emitter_functions *)malloc(sizeof(struct ucl_emitter_functions));
    if (emitter_funcs == NULL) {
        return 0;
    }

    // Initialize the ucl_emitter_functions structure
    emitter_funcs->ucl_emitter_append_character = dummy_append_character;
    emitter_funcs->ucl_emitter_append_len = dummy_append_len;
    emitter_funcs->ucl_emitter_append_int = dummy_append_int;
    emitter_funcs->ucl_emitter_append_double = dummy_append_double;
    emitter_funcs->ucl_emitter_free_func = dummy_free_func;
    emitter_funcs->ud = NULL;

    // Call the function-under-test
    ucl_object_emit_funcs_free(emitter_funcs);

    // Free allocated memory
    free(emitter_funcs);

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

    LLVMFuzzerTestOneInput_31(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
