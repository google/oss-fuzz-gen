#include <stdint.h>
#include <stddef.h>
#include <string.h>  // Include for memcpy
#include <janet.h>

// Fuzzing harness for janet_get_abstract_type
int LLVMFuzzerTestOneInput_164(const uint8_t *data, size_t size) {
    // Ensure size is sufficient to create a Janet object
    if (size < sizeof(Janet)) {
        return 0;
    }

    // Create a Janet object from the input data
    Janet janet_obj;
    memcpy(&janet_obj, data, sizeof(Janet));

    // Call the function-under-test
    const JanetAbstractType *abstract_type = janet_get_abstract_type(janet_obj);

    // Use the result to prevent compiler optimizations from removing the call
    if (abstract_type != NULL) {
        // Do something trivial with abstract_type, like checking its name
        const char *type_name = abstract_type->name;
        if (type_name != NULL) {
            // Just a dummy operation to use type_name
            (void)type_name[0];
        }
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_164(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
