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
  size_t compr_level;
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  const uint8_t *source_data_ptr = Data;
  size_t source_size = Size;
  size_t destination_size = Size;
  qpl_compression_levels compression_level = qpl_default_level;

  if (0 == Size) {
    return 0;
  }

  if (Data[0] & 4) {
    compression_level = qpl_high_level;
  }

  if (sizeof(inflate_properties) < Size) {
    inflate_properties *properties = (inflate_properties *)Data;
    source_data_ptr += sizeof(inflate_properties);
    source_size -= sizeof(inflate_properties);
    destination_size = properties->destination_size;
    compression_level = (properties->compr_level & 1) ? qpl_high_level : qpl_default_level;
    if (0 == destination_size) {
      destination_size = 1;
    }
    destination_size %= (source_size + source_size);
    if (0 == destination_size) {
      destination_size = source_size + source_size;
    }
  }

  std::vector<uint8_t> source(source_data_ptr, source_data_ptr + source_size);
  std::vector<uint8_t> destination(destination_size, 0xaa);

  {
    qpl_histogram histogram{};
    qpl_huffman_table_t huffman_table{};

    qpl_status status = QPL_STS_OK;

    status = qpl_gather_deflate_statistics(source.data(), source.size(), &histogram, compression_level, qpl_path_software);

    if (status != QPL_STS_OK) {
      return 0;
    }

    status = qpl_deflate_huffman_table_create(combined_table_type, qpl_path_software, DEFAULT_ALLOCATOR_C, &huffman_table);
    if (status != QPL_STS_OK) {
      return 0;
    }

    status = qpl_huffman_table_init_with_histogram(huffman_table, &histogram);

    if (status != QPL_STS_OK) {
      qpl_huffman_table_destroy(huffman_table);
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
      qpl_huffman_table_destroy(huffman_table);
      return 0;
    }

    job_ptr->next_in_ptr = source.data();
    job_ptr->available_in = source.size();
    job_ptr->next_out_ptr = destination.data();
    job_ptr->available_out = static_cast<uint32_t>(destination.size());
    job_ptr->huffman_table = huffman_table;
    job_ptr->total_out = 0;

    job_ptr->op = qpl_op_decompress;
    job_ptr->flags = QPL_FLAG_CANNED_MODE | QPL_FLAG_FIRST | QPL_FLAG_LAST;

    status = qpl_execute_job(job_ptr);

    status = qpl_fini_job(job_ptr);

    qpl_huffman_table_destroy(huffman_table);
  }

  return 0;
}
