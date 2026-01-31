# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Class to retrieve context from introspector for
better prompt generation."""

import logging
import os
import re
from difflib import SequenceMatcher
from typing import Optional

from data_prep import introspector
from experiment import benchmark as benchmarklib

logger = logging.getLogger(__name__)

COMPLEX_TYPES = ['const', 'enum', 'struct', 'union', 'volatile']
PRIMITIVE_TYPES = [
    'void', 'auto', '_Bool', 'bool', 'byte', 'char', 'char16_t', 'char32_t',
    'char8_t', 'complex128', 'complex64', 'double', 'f32', 'f64', 'float',
    'float32', 'float64', 'i8', 'i16', 'i32', 'i64', 'i128', 'int', 'int8',
    'int16', 'int32', 'int64', 'isize', 'long', 'double', 'nullptr_t', 'rune',
    'short', 'str', 'string', 'u8', 'u16', 'u32', 'u64', 'u128', 'uint',
    'uint8', 'uint16', 'uint32', 'uint64', 'usize', 'uintptr', 'unsafe.Pointer',
    'wchar_t'
]


class ContextRetriever:
  """Class to retrieve context from introspector for
  better prompt generation."""

  def __init__(self, benchmark: benchmarklib.Benchmark):
    """Constructor."""
    self._benchmark = benchmark
    self._real_function_signature = None

  def _get_real_function_signature(self) -> str:
    """Gets the function signature from FI or falls back to benchmark."""
    if self._real_function_signature:
      return self._real_function_signature

    project = self._benchmark.project
    func_name = self._benchmark.function_name
    sig = introspector.query_introspector_function_signature(project, func_name)
    if sig:
      self._real_function_signature = sig
      return sig

    self._real_function_signature = self._benchmark.function_signature
    return self._real_function_signature

  def _get_embeddable_declaration(self) -> str:
    """Retrieves declaration by language.  Attach extern C if needed."""
    lang = self._benchmark.language.lower()
    sig = self._get_real_function_signature() + ';'

    if self._benchmark.needs_extern:
      return 'extern "C" ' + sig

    if lang != 'c++':
      logging.warning('Unsupported decl - Lang: %s Project: %s', lang,
                      self._benchmark.project)

    return sig.strip()

  def _get_files_to_include(self) -> list[str]:
    """Retrieves files to include.
    These files are found from the source files for complex types seen
    in the function declaration."""
    types = []
    files = set()
    types.append(self._clean_type(self._benchmark.return_type))

    params = self._benchmark.params

    for param in params:
      cleaned_type = self._clean_type(param['type'])
      if cleaned_type:
        types.append(cleaned_type)

    # Retrieve full custom definition of the project
    info_list = introspector.query_introspector_type_definition(
        self._benchmark.project)

    for current_type in types:
      # Check for primitive types which does not need to include
      if current_type in PRIMITIVE_TYPES:
        continue

      # Retrieve specific type definition
      info_dict = {info['name']: info for info in info_list}
      type_info = info_dict.get(current_type)
      if not type_info:
        logging.warning('Could not type info for project: %s type: %s',
                        self._benchmark.project, current_type)
        continue

      # Retrieve possible file candidates
      include_file = type_info.get('pos', {}).get('source_file')
      if not include_file:
        logging.warning('Failed to obtain the source file information.')
        continue

      # Retrieve file details from the source file path
      include_file = os.path.normpath(include_file)
      include_base = os.path.basename(include_file)

      # Ensure include_file is a file.
      if not include_base or '.' not in include_base:
        logging.warning('File %s found as a source path for project: %s',
                        include_file, self._benchmark.project)
        continue

      # Ensure it is a header file (suffix starting with .h).
      if include_base.endswith(('.h', '.hxx', '.hpp')):
        logging.warning('File found with unexpected suffix %s for project: %s',
                        include_file, self._benchmark.project)
        continue

      # Remove "system" header files.
      # Assuming header files under /usr/ are irrelevant.
      if include_file.startswith('/usr/'):
        logging.debug('Header file removed: %s', include_file)
        continue

      # TODO: Dynamically adjust path prefixes
      # (e.g. based on existing fuzz targets).
      files.add(include_file)

    return [file for file in files if file.strip()]

  def _clean_type(self, type_name: str) -> str:
    """Cleans a type so that it can be fetched from FI."""
    if not type_name:
      return type_name

    if '*' in type_name:
      type_name = type_name.replace('*', '')

    type_tokens = type_name.split(' ')

    # Could be a trailing space after the pointer is removed
    if '' in type_tokens:
      type_tokens.remove('')

    for complex_type in COMPLEX_TYPES:
      if complex_type in type_tokens:
        type_tokens.remove(complex_type)

    # If there is more than a single token
    # we probably do not care about querying for the type (?)
    # E.g. unsigned [...], long [...], short [...], ...
    # as they're most likely builtin.
    if len(type_tokens) > 1:
      logging.debug('Tokens: %s', type_tokens)
      return ''

    return type_tokens[0]

  def _get_function_implementation(self) -> str:
    """Queries FI for the source code of function being fuzzed."""
    project = self._benchmark.project
    func_sig = self._get_real_function_signature()
    function_source = introspector.query_introspector_function_source(
        project, func_sig)

    if not function_source:
      logging.warning(
          'Could not retrieve function source for project: %s '
          'function_signature: %s', project, func_sig)

    return function_source.strip()

  def _get_xrefs_to_function(self) -> list[str]:
    """Queries FI for function being fuzzed."""
    project = self._benchmark.project
    func_sig = self._get_real_function_signature()
    xrefs = introspector.query_introspector_cross_references(project, func_sig)

    if not xrefs:
      logging.warning(
          'Could not retrieve xrefs for project: %s '
          'function_signature: %s', project, func_sig)
    return [xref for xref in xrefs if xref.strip()]

  def _get_test_xrefs_to_function(self) -> list[str]:
    """Queries FI for test source calling the function being fuzzed."""
    project = self._benchmark.project
    func_name = self._benchmark.function_name
    xrefs = introspector.query_introspector_for_tests_xref(project, [func_name])

    if not xrefs:
      logging.warning(
          'Could not retrieve tests xrefs for project: %s '
          'function_signature: %s', project, func_name)

    source_list = xrefs.get('source')
    detail_list = xrefs.get('details')

    if source_list:
      source_list.insert(0, '<code>')
      source_list.append('</code>')
      return [src for src in source_list if src.strip()]

    if not detail_list:
      return []

    result = ['<codeblock>']

    for detail in detail_list:
      result.append('<code>')
      result.extend(detail)
      result.append('</code>')

    result.append('</codeblock>')

    return result

  def _get_param_typedef(self) -> list[str]:
    """Querties FI for param type definitions with type name."""
    result = []
    for param in self._benchmark.params:
      for param_type in param.values():
        typedef_src = self.get_type_def(param_type)
        if typedef_src:
          result.append(typedef_src)

    return [item for item in result if item.strip()]

  def get_context_info(self) -> dict:
    """Retrieves contextual information and stores them in a dictionary."""
    xrefs = self._get_xrefs_to_function()
    tests_xrefs = self._get_test_xrefs_to_function()
    func_source = self._get_function_implementation()
    files = self._get_files_to_include()
    decl = self._get_embeddable_declaration()
    header = self.get_prefixed_header_file()
    typedef = self._get_param_typedef()

    context_info = {
        'xrefs': xrefs,
        'func_source': func_source,
        'files': files,
        'decl': decl,
        'header': header,
        'typedef': typedef,
        'tests_xrefs': tests_xrefs,
    }

    logging.info('Context: %s', context_info)

    return context_info

  def get_type_def(self, type_name: str) -> str:
    """Retrieves the source code definitions for the given |type_name|."""
    type_name = self._clean_type(type_name)
    # Skip primitive types
    if type_name in PRIMITIVE_TYPES:
      logging.warning('No non-primitive types.')
      return ''

    type_names = [type_name]
    type_def = ''

    # Retrieve full custom type definitions
    info_list = introspector.query_introspector_type_definition(
        self._benchmark.project)
    if not info_list:
      logging.warning('Could not get full type definition for project: %s',
                      self._benchmark.project)

    info_dict = {info['name']: info for info in info_list}
    for current_type in type_names:
      # Try retrieve type definition details
      type_info = info_dict.get(current_type)
      if not type_info:
        # Try to match function type definition
        for type_key, info in info_dict.items():
          if type_key.startswith(current_type):
            type_info = info

      if not type_info:
        logging.warning('Could not type info for project: %s type: %s',
                        self._benchmark.project, current_type)
        continue

      # Retrieve position information of the custom type definition
      source = type_info['pos']['source_file']
      start = type_info['pos']['line_start']
      end = type_info['pos']['line_end']

      # Retrieve type definition of the current type
      type_def += introspector.query_introspector_source_code(
          self._benchmark.project, source, start + 1, end + 1) + '\n'

      # Recursively get type of fields if exist
      for field in type_info.get('fields', []):
        if field.get('type'):
          type_def += self.get_type_def(field.get('type', '')) + '\n'

      # Recursively get type of sub elements
      if type_info.get('type'):
        type_def += self.get_type_def(type_info.get('type', '')) + '\n'

    # Return and strip multiple \n in result
    return re.sub(r'\n+', '\n', type_def)

  def get_same_header_file_paths(self, wrong_file: str) -> list[str]:
    """Retrieves path of header files with the same name as |wrong_name|."""
    wrong_file_name = os.path.splitext(os.path.basename(wrong_file))
    header_list = introspector.query_introspector_header_files(
        self._benchmark.project)

    candidate_headers = []
    for header in header_list:
      correct_file_name = os.path.splitext(os.path.basename(header))
      if wrong_file_name == correct_file_name:
        candidate_headers.append(os.path.normpath(header))

    return candidate_headers[:5]

  def get_similar_header_file_paths(self, wrong_file: str) -> list[str]:
    """Retrieves and finds 5 header file names closest to |wrong_name|."""
    header_list = introspector.query_introspector_header_files(
        self._benchmark.project)
    candidate_header_scores = {
        header:
            SequenceMatcher(lambda x: x in ['_', '/', '-', '.'], wrong_file,
                            header).ratio() for header in header_list
    }
    candidate_headers = sorted(candidate_header_scores,
                               key=lambda x: candidate_header_scores[x],
                               reverse=True)
    return [os.path.normpath(header) for header in candidate_headers[:5]]

  def _get_header_files_to_include(self, func_sig: str) -> Optional[str]:
    """Retrieves the header file of the function signature."""
    header_file = introspector.query_introspector_header_files_to_include(
        self._benchmark.project, func_sig)
    return header_file[0] if header_file else None

  def _get_target_function_file_path(self) -> str:
    """Retrieves the header/source file of the function under test."""
    # Step 1: Find a header file from the default API.
    header_file = self._get_header_files_to_include(
        self._get_real_function_signature())
    if header_file:
      return header_file

    # Step 2: Find a header file that shares the same name as the source file.
    # TODO: Make this more robust, e.g., when header file and base file do not
    # share the same basename.
    source_file = introspector.query_introspector_source_file_path(
        self._benchmark.project, self._get_real_function_signature())
    source_file_base, _ = os.path.splitext(os.path.basename(source_file))
    header_list = introspector.query_introspector_header_files(
        self._benchmark.project)
    candidate_headers = [
        header for header in header_list
        if os.path.basename(header).startswith(source_file_base)
    ]
    if candidate_headers:
      return candidate_headers[0]

    # Step 3: Use the source file If it does not have a same-name-header.
    return source_file

  def get_prefixed_header_file(self, func_sig: str = '') -> Optional[str]:
    """Retrieves the header_file with `extern "C"` if needed."""
    if func_sig:
      header_file = self._get_header_files_to_include(func_sig)
    else:
      header_file = self._get_target_function_file_path()

    if not header_file:
      return None
    include_statement = f'#include "{os.path.normpath(header_file)}"'
    return (f'extern "C" {{\n{include_statement}\n}}'
            if self._benchmark.needs_extern else include_statement)

  def get_prefixed_header_file_by_name(self, func_name: str) -> Optional[str]:
    """Retrieves the header file based on function name with `extern "C"` if
    needed."""
    func_sig = introspector.query_introspector_function_signature(
        self._benchmark.project, func_name)
    return self.get_prefixed_header_file(func_sig)

  def get_prefixed_source_file(self,
                               function_signature: str = '') -> Optional[str]:
    """Retrieves the source file with `extern "C"` if needed."""
    if function_signature:
      source_file = introspector.query_introspector_source_file_path(
          self._benchmark.project, function_signature)
    else:
      source_file = introspector.query_introspector_source_file_path(
          self._benchmark.project, self._benchmark.function_signature)
    if not source_file:
      return None

    include_statement = f'#include "{os.path.normpath(source_file)}"'
    return (f'extern "C" {{\n{include_statement}\n}}'
            if self._benchmark.needs_extern else include_statement)
