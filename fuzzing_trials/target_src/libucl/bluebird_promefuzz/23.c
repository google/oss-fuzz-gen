#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "ucl.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_23(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Ensure null-terminated string for ucl_object_fromstring
    char *string1 = (char *)malloc(Size + 1);
    if (!string1) return 0;
    memcpy(string1, Data, Size);
    string1[Size] = '\0';

    ucl_object_t *obj1 = ucl_object_fromstring(string1);
    ucl_object_t *array1 = ucl_object_fromstring("[]");
    ucl_object_t *array2 = ucl_object_fromstring("[]");

    if (array1 && array2 && obj1) {
        // Merge two arrays
        ucl_array_merge(array1, array2, true);

        // Insert object into array
        ucl_object_insert_key(array1, obj1, "key1", 0, true);

        // Create another object from string
        ucl_object_t *obj2 = ucl_object_fromstring(string1);
        if (obj2) {
            // Insert second object into array
            ucl_object_insert_key(array1, obj2, "key2", 0, true);

            // Delete key from array
            ucl_object_delete_key(array1, "key1");
        }
    }

    // Cleanup
    if (array1) ucl_object_unref(array1);
    if (array2) ucl_object_unref(array2);
    if (obj1) ucl_object_unref(obj1);

    free(string1);
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

    LLVMFuzzerTestOneInput_23(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
