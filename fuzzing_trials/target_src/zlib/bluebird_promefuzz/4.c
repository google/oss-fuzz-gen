#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "zlib.h"

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_4(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Write input data to a dummy file
    write_dummy_file(Data, Size);

    // Open the file with gzopen
    gzFile file = gzopen("./dummy_file", "rb");
    if (file == NULL) {
        return 0;
    }

    // Prepare buffers
    unsigned char buffer[1024];
    char lineBuffer[256];
    int errnum;

    // gzread
    gzread(file, buffer, sizeof(buffer));

    // gzerror
    gzerror(file, &errnum);

    // gzseek
    gzseek(file, 0, SEEK_SET);

    // gztell
    gztell(file);

    // gztell again
    gztell(file);

    // gzgetc
    gzgetc(file);

    // gzungetc
    gzungetc(Data[0], file);

    // gzgets
    gzgets(file, lineBuffer, sizeof(lineBuffer));

    // gzerror again
    gzerror(file, &errnum);

    // Close the file
    gzclose(file);

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

    LLVMFuzzerTestOneInput_4(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
