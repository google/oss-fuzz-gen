#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <roaring.h>
#include <roaring64.h>

int LLVMFuzzerTestOneInput_115(char *fuzzData, size_t size)
{
	

   bitset_t bitset_shift_leftvar0;
	memset(&bitset_shift_leftvar0, 0, sizeof(bitset_shift_leftvar0));

   bitset_t bitset_contains_allvar0;
	memset(&bitset_contains_allvar0, 0, sizeof(bitset_contains_allvar0));

   roaring64_bitmap_t* roaring64_bitmap_portable_deserialize_safeval1 = roaring64_bitmap_portable_deserialize_safe(fuzzData, size);
	if(!roaring64_bitmap_portable_deserialize_safeval1){
		fprintf(stderr, "err");
		exit(0);	}
   size_t roaring64_bitmap_shrink_to_fitval1 = roaring64_bitmap_shrink_to_fit(roaring64_bitmap_portable_deserialize_safeval1);
	if((int)roaring64_bitmap_shrink_to_fitval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   bitset_shift_left(&bitset_shift_leftvar0, roaring64_bitmap_shrink_to_fitval1);
   bool bitset_contains_allval1 = bitset_contains_all(&bitset_contains_allvar0, &bitset_shift_leftvar0);
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

        LLVMFuzzerTestOneInput_115(data + 2, (size_t)(size - 2));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    