#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <roaring.h>
#include <roaring64.h>

int LLVMFuzzerTestOneInput_192(char *fuzzData, size_t size)
{
	

   char* roaring64_bitmap_portable_serializevar1[size+1];
	sprintf(roaring64_bitmap_portable_serializevar1, "/tmp/2koxg");
   uint16_t intersect_vector16_cardinalityvar0;
	memset(&intersect_vector16_cardinalityvar0, 0, sizeof(intersect_vector16_cardinalityvar0));

   uint16_t intersect_vector16_cardinalityvar2;
	memset(&intersect_vector16_cardinalityvar2, 0, sizeof(intersect_vector16_cardinalityvar2));

   roaring_bitmap_t roaring_bitmap_remove_checkedvar0;
	memset(&roaring_bitmap_remove_checkedvar0, 0, sizeof(roaring_bitmap_remove_checkedvar0));

   roaring64_bitmap_t* roaring64_bitmap_portable_deserialize_safeval1 = roaring64_bitmap_portable_deserialize_safe(fuzzData, size);
	if(!roaring64_bitmap_portable_deserialize_safeval1){
		fprintf(stderr, "err");
		exit(0);	}
   size_t roaring64_bitmap_portable_serializeval1 = roaring64_bitmap_portable_serialize(roaring64_bitmap_portable_deserialize_safeval1, roaring64_bitmap_portable_serializevar1);
	if((int)roaring64_bitmap_portable_serializeval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int32_t intersect_vector16_cardinalityval1 = intersect_vector16_cardinality(&intersect_vector16_cardinalityvar0, roaring64_bitmap_portable_serializeval1, &intersect_vector16_cardinalityvar2, roaring64_bitmap_portable_serializeval1);
	if((int)intersect_vector16_cardinalityval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   bool roaring_bitmap_remove_checkedval1 = roaring_bitmap_remove_checked(&roaring_bitmap_remove_checkedvar0, intersect_vector16_cardinalityval1);
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

        LLVMFuzzerTestOneInput_192(data + 2, (size_t)(size - 2));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    