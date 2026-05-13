#include <stdint.h>
#include <stdlib.h>
#include <zlib.h>

extern int inflateUndermine(z_streamp strm, int subvert);

int LLVMFuzzerTestOneInput_62(const uint8_t *data, size_t size) {
    if (size < sizeof(z_stream)) {
        return 0;
    }

    z_stream stream;
    stream.next_in = (Bytef *)data;
    stream.avail_in = (uInt)size;
    stream.total_in = 0;

    stream.next_out = (Bytef *)malloc(size);
    if (stream.next_out == NULL) {
        return 0;
    }
    stream.avail_out = (uInt)size;
    stream.total_out = 0;

    stream.zalloc = Z_NULL;
    stream.zfree = Z_NULL;
    stream.opaque = Z_NULL;

    int subvert = 1; // Try with subvert as 1

    // Call the function-under-test
    inflateUndermine(&stream, subvert);

    free(stream.next_out);
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

    LLVMFuzzerTestOneInput_62(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
