#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sqlite3.h>

int LLVMFuzzerTestOneInput_25(char *fuzzData, size_t size)
{
	

   sqlite3* sqlite3_openvar1;
	memset(&sqlite3_openvar1, 0, sizeof(sqlite3_openvar1));

   char*** sqlite3_get_tablevar2[256];
	sprintf(sqlite3_get_tablevar2, "/tmp/c7wih");
   int sqlite3_get_tablevarINTsize = sizeof(sqlite3_get_tablevar2);
   sqlite3_int64 sqlite3_deserializevar3;
	memset(&sqlite3_deserializevar3, 0, sizeof(sqlite3_deserializevar3));

   sqlite3_int64 sqlite3_deserializevar4;
	memset(&sqlite3_deserializevar4, 0, sizeof(sqlite3_deserializevar4));

   sqlite3_int64 sqlite3_status64var1;
	memset(&sqlite3_status64var1, 0, sizeof(sqlite3_status64var1));

   sqlite3_int64 sqlite3_status64var2;
	memset(&sqlite3_status64var2, 0, sizeof(sqlite3_status64var2));

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
   int sqlite3_deserializeval1 = sqlite3_deserialize(sqlite3_openvar1, NULL, fuzzData, sqlite3_deserializevar3, sqlite3_deserializevar4, size);
	if((int)sqlite3_deserializeval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int sqlite3_status64val1 = sqlite3_status64(sqlite3_get_tableval1, &sqlite3_status64var1, &sqlite3_status64var2, sqlite3_deserializeval1);
	if((int)sqlite3_status64val1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
