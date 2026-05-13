#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <roaring.h>
#include <roaring64.h>

int LLVMFuzzerTestOneInput_287(char *fuzzData, size_t size)
{
	

   __m256i avx2_harley_seal_popcount256_unionoverload1var0;
	memset(&avx2_harley_seal_popcount256_unionoverload1var0, 0, sizeof(avx2_harley_seal_popcount256_unionoverload1var0));

   __m256i avx2_harley_seal_popcount256_unionoverload1var1;
	memset(&avx2_harley_seal_popcount256_unionoverload1var1, 0, sizeof(avx2_harley_seal_popcount256_unionoverload1var1));

   uint64_t bitset_extract_setbits_avx2var0;
	memset(&bitset_extract_setbits_avx2var0, 0, sizeof(bitset_extract_setbits_avx2var0));

   uint32_t bitset_extract_setbits_avx2var2;
	memset(&bitset_extract_setbits_avx2var2, 0, sizeof(bitset_extract_setbits_avx2var2));

   size_t bitset_extract_setbits_avx2var3 = 1;
   roaring64_bitmap_t* roaring64_bitmap_portable_deserialize_safeval1 = roaring64_bitmap_portable_deserialize_safe(fuzzData, size);
	if(!roaring64_bitmap_portable_deserialize_safeval1){
		fprintf(stderr, "err");
		exit(0);	}
   size_t roaring64_bitmap_shrink_to_fitval1 = roaring64_bitmap_shrink_to_fit(roaring64_bitmap_portable_deserialize_safeval1);
	if((int)roaring64_bitmap_shrink_to_fitval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   uint64_t avx2_harley_seal_popcount256_unionoverload1val1 = avx2_harley_seal_popcount256_union(&avx2_harley_seal_popcount256_unionoverload1var0, &avx2_harley_seal_popcount256_unionoverload1var1, roaring64_bitmap_shrink_to_fitval1);
   size_t bitset_extract_setbits_avx2val1 = bitset_extract_setbits_avx2(&bitset_extract_setbits_avx2var0, avx2_harley_seal_popcount256_unionoverload1val1, &bitset_extract_setbits_avx2var2, bitset_extract_setbits_avx2var3, CROARING_ATOMIC_IMPL_C);
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

        LLVMFuzzerTestOneInput_287(data + 2, (size_t)(size - 2));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    