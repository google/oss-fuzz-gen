#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <roaring.h>
#include <roaring64.h>

int LLVMFuzzerTestOneInput_42(char *fuzzData, size_t size)
{
	

   uint64_t bitset_extract_setbits_avx512var0;
	memset(&bitset_extract_setbits_avx512var0, 0, sizeof(bitset_extract_setbits_avx512var0));

   uint32_t bitset_extract_setbits_avx512var2;
	memset(&bitset_extract_setbits_avx512var2, 0, sizeof(bitset_extract_setbits_avx512var2));

   size_t bitset_extract_setbits_avx512var3 = 1;
   roaring64_bitmap_t* roaring64_bitmap_portable_deserialize_safeval1 = roaring64_bitmap_portable_deserialize_safe(fuzzData, size);
	if(!roaring64_bitmap_portable_deserialize_safeval1){
		fprintf(stderr, "err");
		exit(0);	}
   roaring64_bitmap_xor_inplace(roaring64_bitmap_portable_deserialize_safeval1, roaring64_bitmap_portable_deserialize_safeval1);
   uint64_t roaring64_bitmap_get_cardinalityval1 = roaring64_bitmap_get_cardinality(roaring64_bitmap_portable_deserialize_safeval1);
   size_t bitset_extract_setbits_avx512val1 = bitset_extract_setbits_avx512(&bitset_extract_setbits_avx512var0, roaring64_bitmap_get_cardinalityval1, &bitset_extract_setbits_avx512var2, bitset_extract_setbits_avx512var3, 0);
	if((int)bitset_extract_setbits_avx512val1 < 0){
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

        LLVMFuzzerTestOneInput_42(data + 2, (size_t)(size - 2));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    