#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <roaring.h>
#include <roaring64.h>

int LLVMFuzzerTestOneInput_86(char *fuzzData, size_t size)
{
	

   uint16_t intersect_skewed_uint16var0;
	memset(&intersect_skewed_uint16var0, 0, sizeof(intersect_skewed_uint16var0));

   uint16_t intersect_skewed_uint16var2;
	memset(&intersect_skewed_uint16var2, 0, sizeof(intersect_skewed_uint16var2));

   size_t intersect_skewed_uint16var3 = 1;
   uint16_t intersect_skewed_uint16var4;
	memset(&intersect_skewed_uint16var4, 0, sizeof(intersect_skewed_uint16var4));

   roaring_bitmap_t roaring_bitmap_range_uint32_arrayvar0;
	memset(&roaring_bitmap_range_uint32_arrayvar0, 0, sizeof(roaring_bitmap_range_uint32_arrayvar0));

   size_t roaring_bitmap_range_uint32_arrayvar1 = 1;
   roaring64_bitmap_t* roaring64_bitmap_portable_deserialize_safeval1 = roaring64_bitmap_portable_deserialize_safe(fuzzData, size);
	if(!roaring64_bitmap_portable_deserialize_safeval1){
		fprintf(stderr, "err");
		exit(0);	}
   size_t roaring64_bitmap_shrink_to_fitval1 = roaring64_bitmap_shrink_to_fit(roaring64_bitmap_portable_deserialize_safeval1);
	if((int)roaring64_bitmap_shrink_to_fitval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int32_t intersect_skewed_uint16val1 = intersect_skewed_uint16(&intersect_skewed_uint16var0, roaring64_bitmap_shrink_to_fitval1, &intersect_skewed_uint16var2, intersect_skewed_uint16var3, &intersect_skewed_uint16var4);
	if((int)intersect_skewed_uint16val1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   bool roaring_bitmap_range_uint32_arrayval1 = roaring_bitmap_range_uint32_array(&roaring_bitmap_range_uint32_arrayvar0, roaring_bitmap_range_uint32_arrayvar1, roaring64_bitmap_shrink_to_fitval1, &intersect_skewed_uint16val1);
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

        LLVMFuzzerTestOneInput_86(data + 2, (size_t)(size - 2));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    