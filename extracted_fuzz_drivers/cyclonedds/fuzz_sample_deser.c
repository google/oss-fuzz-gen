#include <dds/ddsrt/heap.h>
#include <ddsi__serdata_cdr.h>
#include <string.h>

#include "fuzz_samples.h"

static void __attribute__((constructor)) print_idl_types_seed() { printf("IDL types seed: %s\n", idl_types_seed); }

static void topic_to_descriptor(struct dds_cdrstream_desc *desc, const dds_topic_descriptor_t *t) {
  memset(desc, 0, sizeof(struct dds_cdrstream_desc));
  dds_cdrstream_desc_init(desc, &dds_cdrstream_default_allocator, t->m_size, t->m_align, t->m_flagset, t->m_ops, NULL, 0);
}

int LLVMFuzzerTestOneInput(void *data, size_t size) {
  uint32_t actual_size;

  for (size_t i = 0; i < sizeof(fixed_types) / sizeof(fixed_types[0]); i++) {
    const struct dds_topic_descriptor *topic = fixed_types[i];
    struct dds_cdrstream_desc desc;
    topic_to_descriptor(&desc, topic);
    if (dds_stream_normalize(data, (uint32_t)size, false, DDSI_RTPS_CDR_ENC_VERSION_2, &desc, false, &actual_size)) {
      void *sample = ddsrt_calloc(1, desc.size);
      dds_istream_t is;
      dds_istream_init(&is, (uint32_t)size, data, DDSI_RTPS_CDR_ENC_VERSION_2);
      dds_stream_read_sample(&is, sample, &dds_cdrstream_default_allocator, &desc);
      dds_stream_free_sample(sample, &dds_cdrstream_default_allocator, desc.ops.ops);
      ddsrt_free(sample);
    }
    dds_cdrstream_desc_fini(&desc, &dds_cdrstream_default_allocator);
  }
  return 0;
}
