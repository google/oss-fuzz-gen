#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <roaring.h>
#include <roaring64.h>

int LLVMFuzzerTestOneInput_237(char *fuzzData, size_t size)
{
	

   char* roaring64_bitmap_portable_serializevar1[size+1];
	sprintf(roaring64_bitmap_portable_serializevar1, "/tmp/ni3ab");
   uint16_t intersect_uint16var0;
	memset(&intersect_uint16var0, 0, sizeof(intersect_uint16var0));

   uint16_t intersect_uint16var2;
	memset(&intersect_uint16var2, 0, sizeof(intersect_uint16var2));

   uint16_t intersect_uint16var4;
	memset(&intersect_uint16var4, 0, sizeof(intersect_uint16var4));

   roaring_bitmap_t roaring_bitmap_rank_manyvar0;
	memset(&roaring_bitmap_rank_manyvar0, 0, sizeof(roaring_bitmap_rank_manyvar0));

   uint32_t roaring_bitmap_rank_manyvar1;
	memset(&roaring_bitmap_rank_manyvar1, 0, sizeof(roaring_bitmap_rank_manyvar1));

   uint64_t roaring_bitmap_rank_manyvar3;
	memset(&roaring_bitmap_rank_manyvar3, 0, sizeof(roaring_bitmap_rank_manyvar3));

   roaring64_bitmap_t* roaring64_bitmap_portable_deserialize_safeval1 = roaring64_bitmap_portable_deserialize_safe(fuzzData, size);
	if(!roaring64_bitmap_portable_deserialize_safeval1){
		fprintf(stderr, "err");
		exit(0);	}
   size_t roaring64_bitmap_portable_serializeval1 = roaring64_bitmap_portable_serialize(roaring64_bitmap_portable_deserialize_safeval1, roaring64_bitmap_portable_serializevar1);
	if((int)roaring64_bitmap_portable_serializeval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int32_t intersect_uint16val1 = intersect_uint16(&intersect_uint16var0, roaring64_bitmap_portable_serializeval1, &intersect_uint16var2, roaring64_bitmap_portable_serializeval1, &intersect_uint16var4);
	if((int)intersect_uint16val1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   roaring_bitmap_rank_many(&roaring_bitmap_rank_manyvar0, &roaring_bitmap_rank_manyvar1, &intersect_uint16val1, &roaring_bitmap_rank_manyvar3);
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

        LLVMFuzzerTestOneInput_237(data + 2, (size_t)(size - 2));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    