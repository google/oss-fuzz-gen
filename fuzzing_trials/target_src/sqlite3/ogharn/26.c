#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sqlite3.h>

int LLVMFuzzerTestOneInput_26(char *fuzzData, size_t size)
{
	

   sqlite3* sqlite3_openvar1;
	memset(&sqlite3_openvar1, 0, sizeof(sqlite3_openvar1));

   char*** sqlite3_get_tablevar2[256];
	sprintf(sqlite3_get_tablevar2, "/tmp/dp1kb");
   int sqlite3_get_tablevarINTsize = sizeof(sqlite3_get_tablevar2);
   char* sqlite3_deserializevar1[256];
	sprintf(sqlite3_deserializevar1, "/tmp/adg0r");
   sqlite3_int64 sqlite3_deserializevar3;
	memset(&sqlite3_deserializevar3, 0, sizeof(sqlite3_deserializevar3));

   sqlite3_int64 sqlite3_deserializevar4;
	memset(&sqlite3_deserializevar4, 0, sizeof(sqlite3_deserializevar4));

   int sqlite3_os_initval1 = sqlite3_os_init();
   int sqlite3_openval1 = sqlite3_open(":memory:", &sqlite3_openvar1);
	if((int)sqlite3_openval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
	if(!sqlite3_openvar1){
		fprintf(stderr, "err");
		exit(0);	}
   int sqlite3_get_tableval1 = sqlite3_get_table(sqlite3_openvar1, fuzzData, sqlite3_get_tablevar2, &sqlite3_get_tablevarINTsize, &sqlite3_os_initval1, &fuzzData);
	if((int)sqlite3_get_tableval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
	if(!sqlite3_get_tablevar2){
		fprintf(stderr, "err");
		exit(0);	}
	if(!fuzzData){
		fprintf(stderr, "err");
		exit(0);	}
   unsigned char* sqlite3_serializeval1 = sqlite3_serialize(sqlite3_openvar1, NULL, NULL, sizeof(NULL));
	if(!sqlite3_serializeval1){
		fprintf(stderr, "err");
		exit(0);	}
   int sqlite3_deserializeval1 = sqlite3_deserialize(sqlite3_openvar1, sqlite3_deserializevar1, fuzzData, sqlite3_deserializevar3, sqlite3_deserializevar4, size);
	if((int)sqlite3_deserializeval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
