#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static Janet dummy_cfunction(int32_t argc, Janet *argv) {
    // A dummy C function for testing
    (void) argc;
    (void) argv;
    return janet_wrap_nil();
}

int LLVMFuzzerTestOneInput_1044(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    // Initialize Janet VM
    janet_init();

    // Prepare dummy JanetTable environment
    JanetTable env;
    janet_table_init(&env, 0);

    // Prepare dummy Janet values array
    Janet argv[3];
    argv[0] = janet_wrap_cfunction(dummy_cfunction);
    argv[1] = janet_wrap_cfunction(dummy_cfunction);
    argv[2] = janet_wrap_cfunction(dummy_cfunction);

    // Select an index within bounds for janet_getcfunction and janet_getfunction
    int32_t index = Data[0] % 3;

    // Fuzz janet_getcfunction
    JanetCFunction cfunc = NULL;
    if (janet_checktype(argv[index], JANET_FUNCTION)) {
        cfunc = janet_getcfunction(argv, index);
    }

    // Fuzz janet_getfunction
    JanetFunction *func = NULL;
    if (janet_checktype(argv[index], JANET_FUNCTION)) {
        func = janet_getfunction(argv, index);
    }

    // Write dummy Janet code to a file
    FILE *file = fopen("./dummy_file", "w");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }

    // Fuzz janet_dostring
    Janet out;
    if (Size > 0 && Data[Size - 1] == '\0') {
        janet_dostring(&env, (const char *)Data, "fuzz_source", &out);
    }

    // Fuzz janet_register
    janet_register("dummy_name", dummy_cfunction);

    // Fuzz janet_wrap_cfunction
    Janet wrapped = janet_wrap_cfunction(dummy_cfunction);

    // Fuzz janet_optcfunction

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from janet_wrap_cfunction to janet_array_push
    JanetArray* ret_janet_array_fochv = janet_array(JANET_SANDBOX_SIGNAL);
    if (ret_janet_array_fochv == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_janet_array_fochv) {
    	return 0;
    }
    janet_array_push(ret_janet_array_fochv, wrapped);
    // End mutation: Producer.APPEND_MUTATOR
    
    JanetCFunction opt_cfunc = janet_optcfunction(argv, 3, index, dummy_cfunction);

    // Cleanup
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

    LLVMFuzzerTestOneInput_1044(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
