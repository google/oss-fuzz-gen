#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <roaring.h>
#include <roaring64.h>

int LLVMFuzzerTestOneInput_140(char *fuzzData, size_t size)
{
	

   char* roaring64_bitmap_portable_serializevar1[size+1];
	sprintf(roaring64_bitmap_portable_serializevar1, "/tmp/l64pa");
   uint16_t bitset_set_listvar1;
	memset(&bitset_set_listvar1, 0, sizeof(bitset_set_listvar1));

   uint64_t roaring64_bitmap_contains_rangeoverload3var1;
	memset(&roaring64_bitmap_contains_rangeoverload3var1, 0, sizeof(roaring64_bitmap_contains_rangeoverload3var1));

   roaring64_bitmap_t* roaring64_bitmap_portable_deserialize_safeval1 = roaring64_bitmap_portable_deserialize_safe(fuzzData, size);
	if(!roaring64_bitmap_portable_deserialize_safeval1){
		fprintf(stderr, "err");
		exit(0);	}
   size_t roaring64_bitmap_portable_serializeval1 = roaring64_bitmap_portable_serialize(roaring64_bitmap_portable_deserialize_safeval1, roaring64_bitmap_portable_serializevar1);
	if((int)roaring64_bitmap_portable_serializeval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   bitset_set_list(&roaring64_bitmap_portable_serializeval1, &bitset_set_listvar1, roaring64_bitmap_portable_serializeval1);
   bool roaring64_bitmap_contains_rangeoverload3val1 = roaring64_bitmap_contains_range(roaring64_bitmap_portable_deserialize_safeval1, roaring64_bitmap_contains_rangeoverload3var1, roaring64_bitmap_portable_serializeval1);
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

        LLVMFuzzerTestOneInput_140(data + 2, (size_t)(size - 2));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    