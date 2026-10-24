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

static void initialize_stream(z_streamp strm) {
    strm->zalloc = Z_NULL;
    strm->zfree = Z_NULL;
    strm->opaque = Z_NULL;
    strm->next_in = Z_NULL;
    strm->avail_in = 0;
    strm->next_out = Z_NULL;
    strm->avail_out = 0;
}

int LLVMFuzzerTestOneInput_12(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    z_stream strm;
    initialize_stream(&strm);

    int ret = inflateInit2_(&strm, 15, ZLIB_VERSION, sizeof(z_stream));
    if (ret != Z_OK) {
        return 0;
    }

    uLong crc = crc32(0L, Z_NULL, 0);


    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from crc32 to crc32_combine
    uLong ret_crc32_combine_gen64_kwrln = crc32_combine_gen64(0);

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from crc32_combine_gen64 to deflateBound
    uLong ret_deflateBound_tjwdy = deflateBound(0, ret_crc32_combine_gen64_kwrln);
    // End mutation: Producer.APPEND_MUTATOR
    
    off_t ret_gzoffset_wzaaf = gzoffset(0);

    // Begin mutation: Producer.SPLICE_MUTATOR - Spliced data flow from gzoffset to gzseek using the plateau pool
    gzFile file = gzopen("./dummy_file", "rb");
    off_t ret_gzseek_pmcmv = gzseek(file, ret_gzoffset_wzaaf, SEEK_SET);
    // End mutation: Producer.SPLICE_MUTATOR
    
    uLong ret_crc32_combine_vaoix = crc32_combine(ret_crc32_combine_gen64_kwrln, crc, ret_gzoffset_wzaaf);
    // End mutation: Producer.APPEND_MUTATOR
    
    strm.next_in = (Bytef *)Data;
    strm.avail_in = Size;

    unsigned char out_buffer[1024];
    strm.next_out = out_buffer;
    strm.avail_out = sizeof(out_buffer);

    ret = inflate(&strm, Z_NO_FLUSH);
    crc = crc32(crc, out_buffer, sizeof(out_buffer) - strm.avail_out);

    inflateEnd(&strm);

    strm.next_in = (Bytef *)Data;
    strm.avail_in = Size;
    strm.next_out = out_buffer;
    strm.avail_out = sizeof(out_buffer);

    ret = deflateInit2_(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15, 8, Z_DEFAULT_STRATEGY, ZLIB_VERSION, sizeof(z_stream));
    if (ret != Z_OK) {
        return 0;
    }

    const Bytef dictionary[] = "dummy_dictionary";
    deflateSetDictionary(&strm, dictionary, sizeof(dictionary));

    deflatePrime(&strm, 3, 5);

    deflateEnd(&strm);

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

    LLVMFuzzerTestOneInput_12(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
