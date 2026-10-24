#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "janet.h"

static JanetString create_janet_string(const uint8_t *Data, size_t Size) {
    if (Size == 0) return janet_cstring("");
    char *cstring = (char *)malloc(Size + 1);
    if (!cstring) return janet_cstring("");
    memcpy(cstring, Data, Size);
    cstring[Size] = '\0';
    JanetString result = janet_cstring(cstring);
    free(cstring);
    return result;
}

int LLVMFuzzerTestOneInput_782(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    // Ensure Janet is initialized
    janet_init();

    // Test janet_cstring
    JanetString janetStr = create_janet_string(Data, Size);

    // Test janet_keyeq
    Janet x;
    x.pointer = (void *)janetStr;
    janet_keyeq(x, (const char *)Data);

    // Test janet_symeq
    janet_symeq(x, (const char *)Data);

    // Test janet_getcstring
    Janet argv[1];
    argv[0].pointer = (void *)janetStr;
    if (janet_checktype(argv[0], JANET_STRING)) {
        janet_getcstring(argv, 0);
    }

    // Test janet_streq
    janet_streq(x, (const char *)Data);

    // Ensure null-terminated C string for janet_cstrcmp
    char *cstring = (char *)malloc(Size + 1);
    if (cstring) {
        memcpy(cstring, Data, Size);
        cstring[Size] = '\0';
        // Test janet_cstrcmp
        janet_cstrcmp(janetStr, cstring);
        free(cstring);
    }

    // Cleanup Janet
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

    LLVMFuzzerTestOneInput_782(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
