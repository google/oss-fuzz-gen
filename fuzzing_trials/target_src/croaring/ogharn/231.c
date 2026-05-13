#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <roaring.h>
#include <roaring64.h>

int LLVMFuzzerTestOneInput_231(char *fuzzData, size_t size)
{
	

   __m256i avx2_harley_seal_popcount256_unionoverload1var0;
	memset(&avx2_harley_seal_popcount256_unionoverload1var0, 0, sizeof(avx2_harley_seal_popcount256_unionoverload1var0));

   __m256i avx2_harley_seal_popcount256_unionoverload1var1;
	memset(&avx2_harley_seal_popcount256_unionoverload1var1, 0, sizeof(avx2_harley_seal_popcount256_unionoverload1var1));

   run_container_t run_container_rank_manyvar0;
	memset(&run_container_rank_manyvar0, 0, sizeof(run_container_rank_manyvar0));

   uint32_t run_container_rank_manyvar2;
	memset(&run_container_rank_manyvar2, 0, sizeof(run_container_rank_manyvar2));

   uint32_t run_container_rank_manyvar3;
	memset(&run_container_rank_manyvar3, 0, sizeof(run_container_rank_manyvar3));

   roaring64_bitmap_t* roaring64_bitmap_portable_deserialize_safeval1 = roaring64_bitmap_portable_deserialize_safe(fuzzData, size);
	if(!roaring64_bitmap_portable_deserialize_safeval1){
		fprintf(stderr, "err");
		exit(0);	}
   size_t roaring64_bitmap_shrink_to_fitval1 = roaring64_bitmap_shrink_to_fit(roaring64_bitmap_portable_deserialize_safeval1);
	if((int)roaring64_bitmap_shrink_to_fitval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   uint64_t avx2_harley_seal_popcount256_unionoverload1val1 = avx2_harley_seal_popcount256_union(&avx2_harley_seal_popcount256_unionoverload1var0, &avx2_harley_seal_popcount256_unionoverload1var1, roaring64_bitmap_shrink_to_fitval1);
   uint32_t run_container_rank_manyval1 = run_container_rank_many(&run_container_rank_manyvar0, roaring64_bitmap_shrink_to_fitval1, &run_container_rank_manyvar2, &run_container_rank_manyvar3, &avx2_harley_seal_popcount256_unionoverload1val1);
	if((int)run_container_rank_manyval1 < 0){
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

        LLVMFuzzerTestOneInput_231(data + 2, (size_t)(size - 2));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    