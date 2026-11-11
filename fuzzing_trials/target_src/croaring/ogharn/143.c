#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <roaring.h>
#include <roaring64.h>

int LLVMFuzzerTestOneInput_143(char *fuzzData, size_t size)
{
	

   uint64_t roaring64_bitmap_flip_closedvar1;
	memset(&roaring64_bitmap_flip_closedvar1, 0, sizeof(roaring64_bitmap_flip_closedvar1));

   uint64_t roaring64_bitmap_flip_closedvar2;
	memset(&roaring64_bitmap_flip_closedvar2, 0, sizeof(roaring64_bitmap_flip_closedvar2));

   uint16_t intersect_skewed_uint16var0;
	memset(&intersect_skewed_uint16var0, 0, sizeof(intersect_skewed_uint16var0));

   size_t intersect_skewed_uint16var1 = 1;
   uint16_t intersect_skewed_uint16var2;
	memset(&intersect_skewed_uint16var2, 0, sizeof(intersect_skewed_uint16var2));

   uint16_t intersect_skewed_uint16var4;
	memset(&intersect_skewed_uint16var4, 0, sizeof(intersect_skewed_uint16var4));

   roaring64_bitmap_t* roaring64_bitmap_portable_deserialize_safeval1 = roaring64_bitmap_portable_deserialize_safe(fuzzData, size);
	if(!roaring64_bitmap_portable_deserialize_safeval1){
		fprintf(stderr, "err");
		exit(0);	}
   roaring64_bitmap_t* roaring64_bitmap_flip_closedval1 = roaring64_bitmap_flip_closed(roaring64_bitmap_portable_deserialize_safeval1, roaring64_bitmap_flip_closedvar1, roaring64_bitmap_flip_closedvar2);
	if(!roaring64_bitmap_flip_closedval1){
		fprintf(stderr, "err");
		exit(0);	}
   size_t roaring64_bitmap_portable_size_in_bytesval1 = roaring64_bitmap_portable_size_in_bytes(roaring64_bitmap_flip_closedval1);
   int32_t intersect_skewed_uint16val1 = intersect_skewed_uint16(&intersect_skewed_uint16var0, intersect_skewed_uint16var1, &intersect_skewed_uint16var2, roaring64_bitmap_portable_size_in_bytesval1, &intersect_skewed_uint16var4);
	if((int)intersect_skewed_uint16val1 < 0){
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

        LLVMFuzzerTestOneInput_143(data + 2, (size_t)(size - 2));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    