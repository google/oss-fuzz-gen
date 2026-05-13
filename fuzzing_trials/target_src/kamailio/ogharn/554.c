#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <hf.h>
#include <keys.h>
#include <msg_parser.h>
#include <parse_addr_spec.h>
#include <parse_allow.h>
#include <parse_body.h>
#include <parse_content.h>
#include <parse_cseq.h>
#include <parse_date.h>
#include <parse_def.h>
#include <parse_disposition.h>
#include <parse_diversion.h>
#include <parse_event.h>
#include <parse_expires.h>
#include <parse_fline.h>
#include <parse_from.h>
#include <parse_hname2.h>
#include <parse_identity.h>
#include <parse_identityinfo.h>
#include <parse_methods.h>
#include <parse_nameaddr.h>
#include <parse_option_tags.h>
#include <parse_param.h>
#include <parse_ppi_pai.h>
#include <parse_privacy.h>
#include <parse_refer_to.h>
#include <parse_require.h>
#include <parse_retry_after.h>
#include <parse_rpid.h>
#include <parse_rr.h>
#include <parse_sipifmatch.h>
#include <parse_subscription_state.h>
#include <parse_supported.h>
#include <parse_to.h>
#include <parse_uri.h>
#include <parse_via.h>
#include <parser_f.h>

int LLVMFuzzerTestOneInput_554(char *fuzzData, size_t size)
{
	

   struct sip_uri parse_urivar2;
	memset(&parse_urivar2, 0, sizeof(parse_urivar2));

   struct msg_start parse_first_linevar2;
	memset(&parse_first_linevar2, 0, sizeof(parse_first_linevar2));

   struct to_body parse_tovar2;
	memset(&parse_tovar2, 0, sizeof(parse_tovar2));

   char* parse_sip_header_namevar0[size+1];
	sprintf(parse_sip_header_namevar0, "/tmp/1cfl6");
   hdr_field_t parse_sip_header_namevar2;
	memset(&parse_sip_header_namevar2, 0, sizeof(parse_sip_header_namevar2));

   int parse_urival1 = parse_uri(fuzzData, size, &parse_urivar2);
	if((int)parse_urival1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   char* parse_first_lineval1 = parse_first_line(fuzzData, size, &parse_first_linevar2);
	if(!parse_first_lineval1){
		fprintf(stderr, "err");
		exit(0);	}
   char* parse_toval1 = parse_to(parse_first_lineval1, fuzzData, &parse_tovar2);
	if(!parse_toval1){
		fprintf(stderr, "err");
		exit(0);	}
   char* parse_sip_header_nameval1 = parse_sip_header_name(parse_sip_header_namevar0, parse_toval1, &parse_sip_header_namevar2, sizeof(parse_toval1), parse_urival1);
	if(!parse_sip_header_nameval1){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
