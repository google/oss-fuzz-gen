#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <roaring.h>
#include <roaring64.h>

int LLVMFuzzerTestOneInput_62(char *fuzzData, size_t size)
{
	

   uint32_t intersection_uint32_cardvar0;
	memset(&intersection_uint32_cardvar0, 0, sizeof(intersection_uint32_cardvar0));

   uint32_t intersection_uint32_cardvar2;
	memset(&intersection_uint32_cardvar2, 0, sizeof(intersection_uint32_cardvar2));

   roaring64_bitmap_t* roaring64_bitmap_portable_deserialize_safeval1 = roaring64_bitmap_portable_deserialize_safe(fuzzData, size);
	if(!roaring64_bitmap_portable_deserialize_safeval1){
		fprintf(stderr, "err");
		exit(0);	}
   roaring64_bitmap_xor_inplace(roaring64_bitmap_portable_deserialize_safeval1, roaring64_bitmap_portable_deserialize_safeval1);
   uint64_t roaring64_bitmap_get_cardinalityval1 = roaring64_bitmap_get_cardinality(roaring64_bitmap_portable_deserialize_safeval1);
   size_t intersection_uint32_cardval1 = intersection_uint32_card(&intersection_uint32_cardvar0, roaring64_bitmap_get_cardinalityval1, &intersection_uint32_cardvar2, roaring64_bitmap_get_cardinalityval1);
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

        LLVMFuzzerTestOneInput_62(data + 2, (size_t)(size - 2));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    