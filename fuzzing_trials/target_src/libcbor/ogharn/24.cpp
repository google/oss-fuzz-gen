#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <cbor.h>

extern "C" int LLVMFuzzerTestOneInput_24(char *fuzzData, size_t size)
{
	

   struct cbor_load_result cbor_loadvar2;
	memset(&cbor_loadvar2, 0, sizeof(cbor_loadvar2));

   size_t cbor_serialize_mapvar2 = 1;
   cbor_item_t* cbor_loadval1 = cbor_load((cbor_data)fuzzData, size, &cbor_loadvar2);
	if(!cbor_loadval1){
		fprintf(stderr, "err");
		exit(0);	}
   size_t cbor_serialize_mapval1 = cbor_serialize_map(cbor_loadval1, (cbor_mutable_data) fuzzData, cbor_serialize_mapvar2);
	if((int)cbor_serialize_mapval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
