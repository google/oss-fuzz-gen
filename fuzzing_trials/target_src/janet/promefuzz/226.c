// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_init at vm.c:1652:5 in janet.h
// janet_in at value.c:453:7 in janet.h
// janet_nanbox_to_pointer at janet.c:37680:7 in janet.h
// janet_get at value.c:514:7 in janet.h
// janet_nanbox_to_pointer at janet.c:37680:7 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <janet.h>

static void prepare_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_226(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    prepare_dummy_file(Data, Size);

    // Initialize the Janet VM
    janet_init();

    Janet ds;
    Janet key;
    Janet value;
    JanetAbstract abstract;
    JanetTuple tuple;
    int checktype_result;

    // Initialize a dummy Janet data structure
    ds.u64 = 0;
    key.u64 = 0;

    // Fuzz janet_in
    if (Size > 1) {
        ds.u64 = Data[0];
        key.u64 = Data[1];
        value = janet_in(ds, key);
    }

    // Fuzz janet_unwrap_tuple
    tuple = janet_unwrap_tuple(ds);

    // Fuzz janet_checktype
    checktype_result = janet_checktype(ds, (JanetType)(Data[0] % (JANET_POINTER + 1)));

    // Fuzz janet_get
    if (Size > 2) {
        ds.u64 = Data[1];
        key.u64 = Data[2];
        value = janet_get(ds, key);
    }

    // Fuzz janet_unwrap_abstract
    abstract = janet_unwrap_abstract(ds);

    // Deinitialize the Janet VM
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

        if(size < 1 + 1)
            exit(0);

        data = (uint8_t *)malloc((size_t)size);
        if(data == NULL)
            exit(0);

        if(fread(data, (size_t)size, 1, f) != 1)
            exit(0);

        LLVMFuzzerTestOneInput_226(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    