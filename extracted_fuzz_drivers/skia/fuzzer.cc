// Copyright 2021 The Dawn & Tint Authors
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its
//    contributors may be used to endorse or promote products derived from
//    this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include <cstddef>
#include <cstdint>

#include "src/tint/fuzzers/random_generator.h"
#include "src/tint/fuzzers/tint_ast_fuzzer/cli.h"
#include "src/tint/fuzzers/tint_ast_fuzzer/mutator.h"
#include "src/tint/fuzzers/tint_ast_fuzzer/override_cli_params.h"
#include "src/tint/fuzzers/tint_common_fuzzer.h"
#include "src/tint/fuzzers/transform_builder.h"
#include "src/tint/lang/wgsl/reader/reader.h"
#include "src/tint/lang/wgsl/writer/writer.h"
#include "testing/libfuzzer/libfuzzer_exports.h"

namespace tint::fuzzers::ast_fuzzer {
namespace {

CliParams cli_params{};

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  // Parse CLI parameters. `ParseCliParams` will call `exit` if some parameter
  // is invalid.
  cli_params = ParseCliParams(argc, *argv);
  // For some fuzz targets it is desirable to force the values of certain CLI
  // parameters after parsing.
  OverrideCliParams(cli_params);
  return 0;
}

extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t max_size, unsigned seed) {
  Source::File file("test.wgsl", {reinterpret_cast<char *>(data), size});
  auto program = wgsl::reader::Parse(&file);
  if (!program.IsValid()) {
    std::cout << "Trying to mutate an invalid program:" << std::endl << program.Diagnostics() << std::endl;
    return 0;
  }

  // Run the mutator.
  RandomGenerator generator(seed);
  ProbabilityContext probability_context(&generator);
  program = Mutate(std::move(program), &probability_context, cli_params.enable_all_mutations, cli_params.mutation_batch_size, nullptr);

  if (!program.IsValid()) {
    std::cout << "Mutator produced invalid WGSL:" << std::endl << "  seed: " << seed << std::endl << program.Diagnostics() << std::endl;
    return 0;
  }

  auto result = wgsl::writer::Generate(program, wgsl::writer::Options());
  if (!result) {
    std::cout << "Can't generate WGSL for a valid tint::Program:" << std::endl << result.Failure() << std::endl;
    return 0;
  }

  if (result->wgsl.size() > max_size) {
    return 0;
  }

  // No need to worry about the \0 here. The reason is that if \0 is included by
  // developer by mistake, it will be considered a part of the string and will
  // cause all sorts of strange bugs. Thus, unless `data` below is used as a raw
  // C string, the \0 symbol should be ignored.
  std::memcpy( // NOLINT - clang-tidy warns about lack of null termination.
      data, result->wgsl.data(), result->wgsl.size());
  return result->wgsl.size();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 0) {
    return 0;
  }

  struct Target {
    FuzzingTarget fuzzing_target;
    OutputFormat output_format;
    const char *name;
  };

  Target targets[] = {{FuzzingTarget::kWgsl, OutputFormat::kWGSL, "WGSL"}, {FuzzingTarget::kHlsl, OutputFormat::kHLSL, "HLSL"}, {FuzzingTarget::kMsl, OutputFormat::kMSL, "MSL"}, {FuzzingTarget::kSpv, OutputFormat::kSpv, "SPV"}};

  for (auto target : targets) {
    if ((target.fuzzing_target & cli_params.fuzzing_target) != target.fuzzing_target) {
      continue;
    }

    TransformBuilder tb(data, size);
    tb.AddTransform<tint::ast::transform::Robustness>();

    CommonFuzzer fuzzer(InputFormat::kWGSL, target.output_format);
    fuzzer.SetTransformManager(tb.manager(), tb.data_map());

    fuzzer.Run(data, size);
    if (fuzzer.HasErrors()) {
      std::cout << "Fuzzing " << target.name << " produced an error" << std::endl << fuzzer.Diagnostics() << std::endl;
    }
  }

  return 0;
}

} // namespace
} // namespace tint::fuzzers::ast_fuzzer
