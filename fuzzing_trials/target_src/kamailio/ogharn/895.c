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

int LLVMFuzzerTestOneInput_895(char *fuzzData, size_t size)
{
	

   char* parse_viavar1[size+1];
	sprintf(parse_viavar1, "/tmp/bwnnc");
   struct via_body parse_viavar2;
	memset(&parse_viavar2, 0, sizeof(parse_viavar2));

   int parse_retry_aftervar3 = 1;
   unsigned int parse_retry_aftervarU_INTsize = size;
   hdr_field_t parse_sip_header_namevar2;
	memset(&parse_sip_header_namevar2, 0, sizeof(parse_sip_header_namevar2));

   char* parse_tovar0[size+1];
	sprintf(parse_tovar0, "/tmp/bep1q");
   struct to_body parse_tovar2;
	memset(&parse_tovar2, 0, sizeof(parse_tovar2));

   char* parse_viaval1 = parse_via(fuzzData, parse_viavar1, &parse_viavar2);
	if(!parse_viaval1){
		fprintf(stderr, "err");
		exit(0);	}
   char* parse_retry_afterval1 = parse_retry_after(parse_viavar1, fuzzData, &parse_retry_aftervarU_INTsize, &parse_retry_aftervar3);
	if(!parse_retry_afterval1){
		fprintf(stderr, "err");
		exit(0);	}
   char* parse_sip_header_nameval1 = parse_sip_header_name(parse_viavar1, parse_retry_afterval1, &parse_sip_header_namevar2, sizeof(parse_retry_afterval1), 0);
	if(!parse_sip_header_nameval1){
		fprintf(stderr, "err");
		exit(0);	}
   char* parse_toval1 = parse_to(parse_tovar0, parse_sip_header_nameval1, &parse_tovar2);
	if(!parse_toval1){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
