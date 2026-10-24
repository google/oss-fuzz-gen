#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <ucl.h>

// Dummy implementations for the purpose of the fuzzing harness
ucl_object_t* create_dummy_ucl_object() {
    ucl_object_t *obj = ucl_object_typed_new(UCL_OBJECT);
    ucl_object_insert_key(obj, ucl_object_fromstring("value"), "key", 0, false);
    return obj;
}

struct ucl_emitter_functions* create_dummy_emitter_functions() {
    struct ucl_emitter_functions *funcs = malloc(sizeof(struct ucl_emitter_functions));
    // Initialize the function pointers to some dummy functions
    funcs->ucl_emitter_append_character = (int (*)(unsigned char, size_t, void *)) NULL;
    funcs->ucl_emitter_append_len = (int (*)(const unsigned char *, size_t, void *)) NULL;
    funcs->ucl_emitter_free_func = (void (*)(void *)) NULL;
    funcs->ud = NULL;
    return funcs;
}

int LLVMFuzzerTestOneInput_224(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    // Create dummy ucl_object_t instances
    ucl_object_t *obj1 = create_dummy_ucl_object();
    ucl_object_t *obj2 = create_dummy_ucl_object();

    // Create a dummy emitter functions struct
    struct ucl_emitter_functions *funcs = create_dummy_emitter_functions();

    // Use the first byte of data to determine the ucl_emitter value
    enum ucl_emitter emitter_type = (enum ucl_emitter)(data[0] % 3);

    // Call the function under test
    bool result = ucl_object_emit_full(obj1, emitter_type, funcs, obj2);

    // Cleanup
    ucl_object_unref(obj1);
    ucl_object_unref(obj2);
    free(funcs);

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

    LLVMFuzzerTestOneInput_224(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
