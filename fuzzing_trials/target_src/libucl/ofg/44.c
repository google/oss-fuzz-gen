#include <stdint.h>
#include <stddef.h>
#include <ucl.h>

// Define dummy user data destructor and emitter functions
void dummy_dtor_44(void *ud) {
    // Dummy destructor, does nothing
}

void dummy_emitter_44(void *ud) {
    // Dummy emitter, does nothing
}

int LLVMFuzzerTestOneInput_44(const uint8_t *data, size_t size) {
    // Ensure the data is not NULL and has a positive size
    if (data == NULL || size == 0) {
        return 0;
    }

    // Use the data as a pointer for the user data
    void *user_data = (void *)data;

    // Call the function-under-test
    ucl_object_t *obj = ucl_object_new_userdata(dummy_dtor_44, dummy_emitter_44, user_data);

    // Clean up if needed (assuming ucl_object_unref is a valid cleanup function)
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

    LLVMFuzzerTestOneInput_44(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
