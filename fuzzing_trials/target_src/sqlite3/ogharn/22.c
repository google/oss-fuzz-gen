#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sqlite3.h>

int LLVMFuzzerTestOneInput_22(char *fuzzData, size_t size)
{
	

   sqlite3* sqlite3_openvar1;
	memset(&sqlite3_openvar1, 0, sizeof(sqlite3_openvar1));

   char*** sqlite3_get_tablevar2[256];
	sprintf(sqlite3_get_tablevar2, "/tmp/8ff8f");
   int sqlite3_get_tablevar4 = 1;
   char** sqlite3_get_tablevar5[256];
	sprintf(sqlite3_get_tablevar5, "/tmp/s6ifn");
   sqlite3_stmt* sqlite3_prepare_v2var3;
	memset(&sqlite3_prepare_v2var3, 0, sizeof(sqlite3_prepare_v2var3));

   int sqlite3_os_initval1 = sqlite3_os_init();
   int sqlite3_openval1 = sqlite3_open(":memory:", &sqlite3_openvar1);
	if((int)sqlite3_openval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
	if(!sqlite3_openvar1){
		fprintf(stderr, "err");
		exit(0);	}
   int sqlite3_create_function16val1 = sqlite3_create_function16(sqlite3_openvar1, (void*)fuzzData, size, sqlite3_os_initval1, (void*)fuzzData, NULL, NULL, NULL);
	if((int)sqlite3_create_function16val1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int sqlite3_get_tableval1 = sqlite3_get_table(sqlite3_openvar1, NULL, sqlite3_get_tablevar2, NULL, &sqlite3_get_tablevar4, sqlite3_get_tablevar5);
	if((int)sqlite3_get_tableval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
	if(!sqlite3_get_tablevar2){
		fprintf(stderr, "err");
		exit(0);	}
	if(!sqlite3_get_tablevar5){
		fprintf(stderr, "err");
		exit(0);	}
   int sqlite3_prepare_v2val1 = sqlite3_prepare_v2(sqlite3_openvar1, fuzzData, 64, &sqlite3_prepare_v2var3, sqlite3_get_tablevar5);
	if((int)sqlite3_prepare_v2val1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
	if(!sqlite3_prepare_v2var3){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
