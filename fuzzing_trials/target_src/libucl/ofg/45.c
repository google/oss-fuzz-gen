#include <stdint.h>
#include <stdlib.h>
#include <ucl.h>

// Dummy destructor function
void dummy_dtor_45(void *data) {
    // Do nothing
}

// Dummy emitter function
void dummy_emitter_45(void *data) {
    // Do nothing
}

int LLVMFuzzerTestOneInput_45(const uint8_t *data, size_t size) {
    // Ensure size is non-zero to have a valid pointer
    if (size == 0) {
        return 0;
    }

    // Use the first byte of data as a dummy pointer value
    void *user_data = (void *)(uintptr_t)data[0];

    // Call the function-under-test
    ucl_object_t *obj = ucl_object_new_userdata(dummy_dtor_45, dummy_emitter_45, user_data);

    // Clean up if necessary
    if (obj != NULL) {
        ucl_object_unref(obj);
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

    LLVMFuzzerTestOneInput_45(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
