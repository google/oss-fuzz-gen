#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sqlite3.h>

int LLVMFuzzerTestOneInput_104(char *fuzzData, size_t size)
{
	

   sqlite3* sqlite3_openvar1;
	memset(&sqlite3_openvar1, 0, sizeof(sqlite3_openvar1));

   char*** sqlite3_get_tablevar2[256];
	sprintf(sqlite3_get_tablevar2, "/tmp/zcwtv");
   int sqlite3_get_tablevarINTsize = sizeof(sqlite3_get_tablevar2);
   char* sqlite3_open_v2var0[256];
	sprintf(sqlite3_open_v2var0, "/tmp/gifpa");
   char* sqlite3_deserializevar1[256];
	sprintf(sqlite3_deserializevar1, "/tmp/isqzj");
   sqlite3_int64 sqlite3_deserializevar3;
	memset(&sqlite3_deserializevar3, 0, sizeof(sqlite3_deserializevar3));

   sqlite3_int64 sqlite3_deserializevar4;
	memset(&sqlite3_deserializevar4, 0, sizeof(sqlite3_deserializevar4));

   unsigned int sqlite3_deserializevar5 = 1;
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
   int sqlite3_open_v2val1 = sqlite3_open_v2(sqlite3_open_v2var0, &sqlite3_openvar1, sqlite3_get_tableval1, NULL);
	if((int)sqlite3_open_v2val1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
	if(!sqlite3_openvar1){
		fprintf(stderr, "err");
		exit(0);	}
   int sqlite3_deserializeval1 = sqlite3_deserialize(sqlite3_openvar1, sqlite3_deserializevar1, NULL, sqlite3_deserializevar3, sqlite3_deserializevar4, sqlite3_deserializevar5);
	if((int)sqlite3_deserializeval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
