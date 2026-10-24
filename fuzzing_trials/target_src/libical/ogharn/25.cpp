#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <libical/ical.h>

extern "C" int LLVMFuzzerTestOneInput_25(char *fuzzData, size_t size)
{
	
        

   struct icaltimetype icalcomponent_set_dtendvar0;
	memset(&icalcomponent_set_dtendvar0, 0, (sizeof icalcomponent_set_dtendvar0));

   struct icaldurationtype icalcomponent_set_durationvar0;
	memset(&icalcomponent_set_durationvar0, 0, (sizeof icalcomponent_set_durationvar0));

   icalcomponent* icalcomponent_new_from_stringval1 = icalcomponent_new_from_string(fuzzData);

	if(!icalcomponent_new_from_stringval1){
		fprintf(stderr, "err");
		exit(0);	}
   icalcomponent_set_dtend(icalcomponent_new_from_stringval1, icalcomponent_set_dtendvar0);
   icalcomponent_set_duration(icalcomponent_new_from_stringval1, icalcomponent_set_durationvar0);
   icalproperty* icalcomponent_get_current_propertyval1 = icalcomponent_get_current_property(icalcomponent_new_from_stringval1);
	if(!icalcomponent_get_current_propertyval1){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
