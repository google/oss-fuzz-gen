#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <roaring.h>
#include <roaring64.h>

int LLVMFuzzerTestOneInput_14(char *fuzzData, size_t size)
{
	

   __m256i avx2_harley_seal_popcount256_unionoverload1var0;
	memset(&avx2_harley_seal_popcount256_unionoverload1var0, 0, sizeof(avx2_harley_seal_popcount256_unionoverload1var0));

   __m256i avx2_harley_seal_popcount256_unionoverload1var1;
	memset(&avx2_harley_seal_popcount256_unionoverload1var1, 0, sizeof(avx2_harley_seal_popcount256_unionoverload1var1));

   uint16_t intersect_skewed_uint16_cardinalityvar0;
	memset(&intersect_skewed_uint16_cardinalityvar0, 0, sizeof(intersect_skewed_uint16_cardinalityvar0));

   uint16_t intersect_skewed_uint16_cardinalityvar2;
	memset(&intersect_skewed_uint16_cardinalityvar2, 0, sizeof(intersect_skewed_uint16_cardinalityvar2));

   roaring64_bitmap_t* roaring64_bitmap_portable_deserialize_safeval1 = roaring64_bitmap_portable_deserialize_safe(fuzzData, size);
	if(!roaring64_bitmap_portable_deserialize_safeval1){
		fprintf(stderr, "err");
		exit(0);	}
   size_t roaring64_bitmap_shrink_to_fitval1 = roaring64_bitmap_shrink_to_fit(roaring64_bitmap_portable_deserialize_safeval1);
	if((int)roaring64_bitmap_shrink_to_fitval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   uint64_t avx2_harley_seal_popcount256_unionoverload1val1 = avx2_harley_seal_popcount256_union(&avx2_harley_seal_popcount256_unionoverload1var0, &avx2_harley_seal_popcount256_unionoverload1var1, roaring64_bitmap_shrink_to_fitval1);
   int32_t intersect_skewed_uint16_cardinalityval1 = intersect_skewed_uint16_cardinality(&intersect_skewed_uint16_cardinalityvar0, roaring64_bitmap_shrink_to_fitval1, &intersect_skewed_uint16_cardinalityvar2, avx2_harley_seal_popcount256_unionoverload1val1);
	if((int)intersect_skewed_uint16_cardinalityval1 < 0){
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

        LLVMFuzzerTestOneInput_14(data + 2, (size_t)(size - 2));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    