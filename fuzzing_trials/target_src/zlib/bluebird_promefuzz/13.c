#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "zlib.h"

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_13(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    // Prepare the dummy file with the provided data
    write_dummy_file(Data, Size);

    // Open the file for writing in gzip format
    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 1 of gzopen
    gzFile gz_file = gzopen("./dummy_file", (const char *)"r");
    // End mutation: Producer.REPLACE_ARG_MUTATOR
    if (gz_file == NULL) {
        return 0;
    }

    // Use gzputc to write a character
    gzputc(gz_file, Data[0]);

    // Use gzputs to write a string (ensure null-termination)
    char str[256];
    size_t str_len = (Size < 255) ? Size : 255;
    memcpy(str, Data, str_len);
    str[str_len] = '\0';
    gzputs(gz_file, str);

    // Check for errors
    int errnum;
    gzerror(gz_file, &errnum);

    // Use gzprintf to write formatted data
    gzprintf(gz_file, "Formatted data: %d\n", Data[0]);

    // Check for errors again
    gzerror(gz_file, &errnum);

    // Seek to the beginning of the file
    gzseek(gz_file, 0, SEEK_SET);

    // Close the file
    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function gzclose with gzrewind
    gzrewind(gz_file);
    // End mutation: Producer.REPLACE_FUNC_MUTATOR

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

    LLVMFuzzerTestOneInput_13(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
