#include <stdint.h>
#include <stddef.h>
#include <ucl.h>
#include <string.h>
#include <stdlib.h> // Include for malloc and free

extern int LLVMFuzzerTestOneInput_178(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    ucl_object_t *obj1 = ucl_object_typed_new(UCL_OBJECT);
    ucl_object_t *obj2 = ucl_object_typed_new(UCL_OBJECT);
    char *comment = NULL;

    // Ensure size is sufficient for creating a non-null comment
    if (size > 0) {
        // Allocate memory for the comment and copy data into it
        comment = (char *)malloc(size + 1);
        if (comment == NULL) {
            goto cleanup;
        }
        memcpy(comment, data, size);
        comment[size] = '\0'; // Null-terminate the string
    } else {
        // Assign a default non-null comment if size is zero
        comment = strdup("default comment");
    }

    // Call the function-under-test
    ucl_comments_add(obj1, obj2, comment);

cleanup:
    // Clean up resources
    if (obj1 != NULL) {
        ucl_object_unref(obj1);
    }
    if (obj2 != NULL) {
        ucl_object_unref(obj2);
    }
    if (comment != NULL) {
        free(comment);
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

    LLVMFuzzerTestOneInput_178(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
