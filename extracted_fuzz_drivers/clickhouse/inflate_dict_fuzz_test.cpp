/*******************************************************************************
 * Copyright (C) 2022 Intel Corporation
 *
 * SPDX-License-Identifier: MIT
 ******************************************************************************/
#include "iostream"
#include "memory"
#include "string"
#include "vector"

#include "qpl/qpl.h"

struct inflate_properties {
  size_t destination_size;
  size_t dictionary_size;
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  const uint8_t *source_data_ptr = Data;
  const uint8_t *dictionary_data_ptr = Data;
  size_t source_size = Size;
  size_t destination_size = Size;
  size_t dictionary_size = Size;
  qpl_compression_levels compression_level = qpl_default_level;

  if (0 == Size) {
    return 0;
  }

  if ((sizeof(inflate_properties) * 2) < Size) {
    inflate_properties *properties = (inflate_properties *)Data;
    source_data_ptr += sizeof(inflate_properties);
    dictionary_data_ptr = source_data_ptr;
    source_size -= sizeof(inflate_properties);
    destination_size = properties->destination_size;
    dictionary_size &= properties->dictionary_size & (4096 - 1);
    if (properties->dictionary_size & 4096) {
      compression_level = qpl_high_level;
    }
    if (0 == destination_size) {
      destination_size = 1;
    }
    if (0 == dictionary_size) {
      dictionary_size = 1;
    }
    if (source_size <= dictionary_size) {
      dictionary_size %= source_size;
      if (0 == dictionary_size) {
        dictionary_size = 1;
      }
    }
    source_size -= dictionary_size;
    source_data_ptr += dictionary_size;
    destination_size %= (source_size + source_size);
    if (0 == destination_size) {
      destination_size = source_size + source_size;
    }
  }

  std::vector<uint8_t> source(source_data_ptr, source_data_ptr + source_size);
  std::vector<uint8_t> destination(destination_size, 0xaa);

  {
    sw_compression_level sw_level = (qpl_high_level == compression_level) ? LEVEL_9 : LEVEL_3;

    auto dictionary_buffer_size = qpl_get_dictionary_size(sw_level, HW_NONE, dictionary_size);
    auto dictionary_buffer = std::make_unique<uint8_t[]>(dictionary_buffer_size);
    auto dictionary_ptr = reinterpret_cast<qpl_dictionary *>(dictionary_buffer.get());
    qpl_status status = qpl_build_dictionary(dictionary_ptr, sw_level, HW_NONE, dictionary_data_ptr, dictionary_size);
    if (status != QPL_STS_OK) {
      return 0;
    }

    // Get size of the job
    uint32_t job_size = 0;

    status = qpl_get_job_size(qpl_path_software, &job_size);
    if (status != QPL_STS_OK) {
      return 0;
    }

    // Initialize the job
    auto job_buffer = std::make_unique<uint8_t[]>(job_size);
    auto job_ptr = reinterpret_cast<qpl_job *>(job_buffer.get());

    status = qpl_init_job(qpl_path_software, job_ptr);
    if (status != QPL_STS_OK) {
      return 0;
    }

    job_ptr->next_in_ptr = source.data();
    job_ptr->available_in = source.size();
    job_ptr->next_out_ptr = destination.data();
    job_ptr->available_out = static_cast<uint32_t>(destination.size());
    job_ptr->total_out = 0;
    job_ptr->dictionary = dictionary_ptr;

    job_ptr->op = qpl_op_decompress;
    job_ptr->flags = QPL_FLAG_FIRST | QPL_FLAG_LAST;

    status = qpl_execute_job(job_ptr);
  }

  return 0;
}
