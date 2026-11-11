#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <roaring.h>
#include <roaring64.h>

int LLVMFuzzerTestOneInput_175(char *fuzzData, size_t size)
{
	

   uint64_t roaring64_bitmap_flip_closedvar1;
	memset(&roaring64_bitmap_flip_closedvar1, 0, sizeof(roaring64_bitmap_flip_closedvar1));

   uint64_t roaring64_bitmap_flip_closedvar2;
	memset(&roaring64_bitmap_flip_closedvar2, 0, sizeof(roaring64_bitmap_flip_closedvar2));

   size_t bitset_extract_setbits_avx2var1 = 1;
   uint32_t bitset_extract_setbits_avx2var2;
	memset(&bitset_extract_setbits_avx2var2, 0, sizeof(bitset_extract_setbits_avx2var2));

   roaring64_bitmap_t* roaring64_bitmap_portable_deserialize_safeval1 = roaring64_bitmap_portable_deserialize_safe(fuzzData, size);
	if(!roaring64_bitmap_portable_deserialize_safeval1){
		fprintf(stderr, "err");
		exit(0);	}
   roaring64_bitmap_t* roaring64_bitmap_flip_closedval1 = roaring64_bitmap_flip_closed(roaring64_bitmap_portable_deserialize_safeval1, roaring64_bitmap_flip_closedvar1, roaring64_bitmap_flip_closedvar2);
	if(!roaring64_bitmap_flip_closedval1){
		fprintf(stderr, "err");
		exit(0);	}
   size_t roaring64_bitmap_portable_size_in_bytesval1 = roaring64_bitmap_portable_size_in_bytes(roaring64_bitmap_flip_closedval1);
   size_t bitset_extract_setbits_avx2val1 = bitset_extract_setbits_avx2(&roaring64_bitmap_portable_size_in_bytesval1, bitset_extract_setbits_avx2var1, &bitset_extract_setbits_avx2var2, roaring64_bitmap_portable_size_in_bytesval1, ROARING_FLAG_FROZEN);
	if((int)bitset_extract_setbits_avx2val1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
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

        LLVMFuzzerTestOneInput_175(data + 2, (size_t)(size - 2));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    