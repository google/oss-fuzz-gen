#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sqlite3.h>

int LLVMFuzzerTestOneInput_119(char *fuzzData, size_t size)
{
	

   sqlite3* sqlite3_openvar1;
	memset(&sqlite3_openvar1, 0, sizeof(sqlite3_openvar1));

   char*** sqlite3_get_tablevar2[256];
	sprintf(sqlite3_get_tablevar2, "/tmp/4bw37");
   char* sqlite3_strnicmpvar0[256];
	sprintf(sqlite3_strnicmpvar0, "/tmp/tqld5");
   char* sqlite3_strnicmpvar1[256];
	sprintf(sqlite3_strnicmpvar1, "/tmp/o9lmg");
   int sqlite3_os_initval1 = sqlite3_os_init();
   int sqlite3_openval1 = sqlite3_open(":memory:", &sqlite3_openvar1);
	if((int)sqlite3_openval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
	if(!sqlite3_openvar1){
		fprintf(stderr, "err");
		exit(0);	}
   int sqlite3_get_tableval1 = sqlite3_get_table(sqlite3_openvar1, fuzzData, sqlite3_get_tablevar2, NULL, NULL, NULL);
	if((int)sqlite3_get_tableval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
	if(!sqlite3_get_tablevar2){
		fprintf(stderr, "err");
		exit(0);	}
   int sqlite3_strnicmpval1 = sqlite3_strnicmp(sqlite3_strnicmpvar0, sqlite3_strnicmpvar1, sqlite3_get_tableval1);
	if((int)sqlite3_strnicmpval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int sqlite3_db_statusval1 = sqlite3_db_status(sqlite3_openvar1, sqlite3_strnicmpval1, &sqlite3_get_tableval1, &sqlite3_openval1, sqlite3_strnicmpval1);
	if((int)sqlite3_db_statusval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
