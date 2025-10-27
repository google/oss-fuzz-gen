/*
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cassert>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>
#include <unordered_map>

#include "lldb-eval/context.h"
#include "lldb-eval/eval.h"
#include "lldb-eval/parser.h"
#include "lldb/API/SBError.h"
#include "lldb/API/SBExpressionOptions.h"
#include "lldb/API/SBFrame.h"
#include "lldb/API/SBType.h"
#include "lldb/API/SBValue.h"
#include "tools/fuzzer/libfuzzer_common.h"

static fuzzer::LibfuzzerState g_state;

static const char *kLoggingPrefix = "[lldb-eval-fuzzer] ";

// How often to log statistics on UB (e.g. every 500 iterations)?
static const int kUbStatsPeriod = 500;

extern "C" const char *__lsan_default_options() { return "print_suppressions=0"; }

// TODO: LSAN suppressions are needed to avoid OSS-Fuzz reports caused by
// memory leaks in LLDB. Once these leaks are fixed, the function won't be
// necessary anymore.
extern "C" const char *__lsan_default_suppressions() {
  return "leak:printNode(llvm::itanium_demangle::Node const*\n"
         "leak:llvm::itanium_demangle::initializeOutputStream";
}

const char *maybe_null(const char *str) { return str == nullptr ? "null" : str; }

bool compare_types(lldb::SBType lhs, lldb::SBType rhs) {
  const std::string lhs_str = maybe_null(lhs.GetName());
  const std::string rhs_str = maybe_null(rhs.GetName());

  if ((lhs_str == "std::nullptr_t" && rhs_str == "nullptr_t") || (lhs_str == "nullptr_t" && rhs_str == "std::nullptr_t")) {
    return true;
  }

  return lhs_str == rhs_str;
}

void log(const char *format, ...) {
  fprintf(stderr, kLoggingPrefix);
  va_list args;
  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);
  fprintf(stderr, "\n");
}

void log_separator() { log("====================================================================="); }

void log_expr(const std::string &expr) { log("expr: %s", expr.c_str()); }

void log_lldb_eval_error(const std::string &expr, lldb_eval::Error error) {
  log_expr(expr);
  log(" cause: lldb-eval error\n");
  log(" error: %s", error.message().c_str());
  log_separator();
}

void log_lldb_error(const std::string &expr, lldb::SBError error) {
  log_expr(expr);
  log(" cause: lldb error");
  log(" error: %s", error.GetCString());
  log_separator();
}

void log_type_mismatch(const std::string &expr, const char *lldb_type, const char *lldb_eval_type) {
  log_expr(expr);
  log(" cause: type mismatch");
  log(" lldb type     : %s", lldb_type);
  log(" lldb-eval type: %s", lldb_eval_type);
  log_separator();
}

void log_value_mismatch(const std::string &expr, const std::string &lldb_value, const std::string &lldb_eval_value) {
  log_expr(expr);
  log(" cause: value mismatch");
  log(" lldb value     : %s", lldb_value.c_str());
  log(" lldb-eval value: %s", lldb_eval_value.c_str());
  log_separator();
}

void report_undefined_behaviour(lldb_eval::UbStatus status) {
  using lldb_eval::UbStatus;
  static std::unordered_map<UbStatus, size_t> stats;
  static size_t count = 0;

  stats[status]++;
  count++;

  if (count % kUbStatsPeriod == 0) {
    // Log statistics every `kUbStatsPeriod` iterations.
    log("UB stats: (kOk: %zu, kDivisionByZero: %zu, kInvalidCast: %zu, "
        "kInvalidShift: %zu, kNullptrArithmetic: %zu, kInvalidPtrDiff: %zu, "
        "kDivisionByMinusOne: %zu)",
        stats[UbStatus::kOk], stats[UbStatus::kDivisionByZero], stats[UbStatus::kInvalidCast], stats[UbStatus::kInvalidShift], stats[UbStatus::kNullptrArithmetic], stats[UbStatus::kInvalidPtrDiff], stats[UbStatus::kDivisionByMinusOne]);
    log_separator();
  }
}

extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t max_size, unsigned int seed) { return g_state.custom_mutate(data, size, max_size, seed); }

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  std::string expr = g_state.input_to_expr(data, size);

  auto sm = lldb_eval::SourceManager::Create(expr);
  auto ctx = lldb_eval::Context::Create(sm, g_state.frame());

  // lldb-eval evaluation.
  lldb_eval::Error err;
  lldb_eval::Parser parser(ctx);
  lldb_eval::ExprResult tree = parser.Run(err);
  if (err) {
    log_lldb_eval_error(expr, err);
    abort();
  }

  lldb_eval::Interpreter eval(g_state.target(), sm);
  lldb::SBValue lldb_eval_value = eval.Eval(tree.get(), err).inner_value();
  if (err) {
    log_lldb_eval_error(expr, err);
    abort();
  }

  lldb_eval::UbStatus ub_status = err.ub_status();

  // Process statistics on UB.
  report_undefined_behaviour(ub_status);

  // LLDB evaluation.
  lldb::SBExpressionOptions opts;
  opts.SetAutoApplyFixIts(false);
  lldb::SBValue lldb_value = g_state.frame().EvaluateExpression(expr.c_str(), opts);
  if (lldb_value.GetError().Fail()) {
    // Some errors are caused by undefined behaviour (e.g. division by zero).
    // Consider only errors that were caused if UB wasn't detected.
    if (ub_status != lldb_eval::UbStatus::kOk) {
      return 0;
    }
    log_lldb_error(expr, lldb_value.GetError());
    abort();
  }

  // Check type mismatch.
  lldb::SBType lldb_type = lldb_value.GetType();
  lldb::SBType lldb_eval_type = lldb_eval_value.GetType();
  if (!compare_types(lldb_type, lldb_eval_type)) {
    log_type_mismatch(expr, maybe_null(lldb_type.GetName()), maybe_null(lldb_eval_type.GetName()));
    abort();
  }

  if (err.ub_status() != lldb_eval::UbStatus::kOk) {
    // Don't compare values if undefined behaviour was detected.
    return 0;
  }

  std::string lldb_value_str = maybe_null(lldb_value.GetValue());
  std::string lldb_eval_value_str = maybe_null(lldb_eval_value.GetValue());

  if (lldb_eval_value_str != lldb_value_str) {
    log_value_mismatch(expr, lldb_value_str, lldb_eval_value_str);
    abort();
  }

  return 0;
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) { return g_state.init(argc, argv); }
