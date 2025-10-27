// Copyright 2022 The Dawn & Tint Authors
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

#include <fstream>
#include <iostream>
#include <string>
#include <unordered_set>

#include <thread>

#include "src/tint/lang/glsl/writer/writer.h"
#include "src/tint/lang/hlsl/writer/writer.h"
#include "src/tint/lang/msl/writer/writer.h"
#include "src/tint/lang/spirv/writer/writer.h"
#include "src/tint/lang/wgsl/helpers/apply_substitute_overrides.h"
#include "src/tint/lang/wgsl/helpers/flatten_bindings.h"
#include "src/tint/lang/wgsl/inspector/inspector.h"
#include "src/tint/lang/wgsl/reader/reader.h"
#include "src/tint/lang/wgsl/sem/module.h"
#include "src/tint/lang/wgsl/writer/writer.h"
#include "src/tint/utils/math/hash.h"

static constexpr size_t kNumThreads = 8;

[[noreturn]] void TintInternalCompilerErrorReporter(const tint::InternalCompilerError &err) {
  std::cerr << err.Error() << std::endl;
  __builtin_trap();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  tint::SetInternalCompilerErrorReporter(&TintInternalCompilerErrorReporter);

  std::string str(reinterpret_cast<const char *>(data), size);
  auto file = std::make_unique<tint::Source::File>("test.wgsl", str);
  auto program = tint::wgsl::reader::Parse(file.get());
  if (!program.IsValid()) {
    return 0;
  }

  if (program.Sem().Module()->Extensions().Contains(tint::wgsl::Extension::kChromiumExperimentalPixelLocal)) {
    return 0; // Not supported
  }

  if (auto transformed = tint::wgsl::ApplySubstituteOverrides(program)) {
    program = std::move(*transformed);
    if (!program.IsValid()) {
      return 0;
    }
  }

  tint::inspector::Inspector inspector(program);
  auto entry_points = inspector.GetEntryPoints();
  std::string entry_point = entry_points.empty() ? "" : entry_points.front().name;

  std::array<std::thread, kNumThreads> threads;

  for (size_t thread_idx = 0; thread_idx < kNumThreads; thread_idx++) {
    auto thread = std::thread([&program, thread_idx, entry_point] {
      enum class Writer {
#if TINT_BUILD_GLSL_WRITER
        kGLSL,
#endif
#if TINT_BUILD_HLSL_WRITER
        kHLSL,
#endif
#if TINT_BUILD_MSL_WRITER
        kMSL,
#endif
#if TINT_BUILD_SPV_WRITER
        kSPIRV,
#endif
#if TINT_BUILD_WGSL_WRITER
        kWGSL,
#endif
        kCount
      };
      switch (static_cast<Writer>(thread_idx % static_cast<size_t>(Writer::kCount))) {
#if TINT_BUILD_WGSL_WRITER
      case Writer::kWGSL: {
        (void)tint::wgsl::writer::Generate(program, {});
        break;
      }
#endif // TINT_BUILD_WGSL_WRITER

#if TINT_BUILD_SPV_WRITER
      case Writer::kSPIRV: {
        (void)tint::spirv::writer::Generate(program, {});
        break;
      }
#endif // TINT_BUILD_SPV_WRITER

#if TINT_BUILD_HLSL_WRITER
      case Writer::kHLSL: {
        (void)tint::hlsl::writer::Generate(program, {});
        break;
      }
#endif // TINT_BUILD_HLSL_WRITER

#if TINT_BUILD_GLSL_WRITER
      case Writer::kGLSL: {
        (void)tint::glsl::writer::Generate(program, {}, entry_point);
        break;
      }
#endif // TINT_BUILD_GLSL_WRITER

#if TINT_BUILD_MSL_WRITER
      case Writer::kMSL: {
        // Remap resource numbers to a flat namespace.
        if (auto flattened = tint::wgsl::FlattenBindings(program)) {
          (void)tint::msl::writer::Generate(flattened.value(), {});
        }
        break;
      }
#endif // TINT_BUILD_MSL_WRITER

      case Writer::kCount:
        break;
      }
    });
    threads[thread_idx] = std::move(thread);
  }

  for (auto &thread : threads) {
    thread.join();
  }

  return 0;
}
