#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <roaring.h>
#include <roaring64.h>

int LLVMFuzzerTestOneInput_222(char *fuzzData, size_t size)
{
	

   size_t fast_union_uint16var3 = 1;
   roaring64_bitmap_t* roaring64_bitmap_portable_deserialize_safeval1 = roaring64_bitmap_portable_deserialize_safe(fuzzData, size);
	if(!roaring64_bitmap_portable_deserialize_safeval1){
		fprintf(stderr, "err");
		exit(0);	}
   roaring64_bitmap_xor_inplace(roaring64_bitmap_portable_deserialize_safeval1, roaring64_bitmap_portable_deserialize_safeval1);
   uint64_t roaring64_bitmap_xor_cardinalityval1 = roaring64_bitmap_xor_cardinality(roaring64_bitmap_portable_deserialize_safeval1, roaring64_bitmap_portable_deserialize_safeval1);
   size_t fast_union_uint16val1 = fast_union_uint16(NULL, roaring64_bitmap_xor_cardinalityval1, NULL, fast_union_uint16var3, NULL);
	if((int)fast_union_uint16val1 < 0){
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

        LLVMFuzzerTestOneInput_222(data + 2, (size_t)(size - 2));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    