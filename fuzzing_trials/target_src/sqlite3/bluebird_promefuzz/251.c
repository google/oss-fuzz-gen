#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "sqlite3.h"

static void initialize_string(char *dest, const uint8_t *data, size_t size, size_t max_len) {
    size_t len = size < max_len ? size : max_len - 1;
    memcpy(dest, data, len);
    dest[len] = '\0';
}

int LLVMFuzzerTestOneInput_251(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    char str1[256];
    char str2[256];
    char str3[256];
    char str4[256];
    char str5[256];
    char str6[256];
    char str7[256];
    char str8[256];
    char str9[256];
    char str10[256];

    size_t offset = 0;
    size_t segment_size = Size / 10;

    initialize_string(str1, Data + offset, segment_size, sizeof(str1));
    offset += segment_size;
    initialize_string(str2, Data + offset, segment_size, sizeof(str2));
    offset += segment_size;
    initialize_string(str3, Data + offset, segment_size, sizeof(str3));
    offset += segment_size;
    initialize_string(str4, Data + offset, segment_size, sizeof(str4));
    offset += segment_size;
    initialize_string(str5, Data + offset, segment_size, sizeof(str5));
    offset += segment_size;
    initialize_string(str6, Data + offset, segment_size, sizeof(str6));
    offset += segment_size;
    initialize_string(str7, Data + offset, segment_size, sizeof(str7));
    offset += segment_size;
    initialize_string(str8, Data + offset, segment_size, sizeof(str8));
    offset += segment_size;
    initialize_string(str9, Data + offset, segment_size, sizeof(str9));
    offset += segment_size;
    initialize_string(str10, Data + offset, Size - offset, sizeof(str10));

    sqlite3_stricmp(str1, str2);
    sqlite3_stricmp(str3, str4);
    sqlite3_stricmp(str5, str6);
    sqlite3_strnicmp(str7, str8, strlen(str8));
    sqlite3_stricmp(str9, str10);
    sqlite3_stricmp(str1, str3);
    sqlite3_stricmp(str4, str5);
    sqlite3_strglob(str6, str7);
    sqlite3_strglob(str8, str9);
    sqlite3_stricmp(str10, str1);

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

    LLVMFuzzerTestOneInput_251(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
