"""Class to retrieve context from introspector for
better prompt generation."""

import logging
import os
from difflib import SequenceMatcher
from typing import Any, Optional

from data_prep import introspector
from experiment import benchmark as benchmarklib

COMPLEX_TYPES = ['const', 'enum', 'struct', 'union', 'volatile']


class ContextRetriever:
  """Class to retrieve context from introspector for
  better prompt generation."""

  def __init__(self, benchmark: benchmarklib.Benchmark):
    """Constructor."""
    self._benchmark = benchmark

  def _get_embeddable_declaration(self) -> str:
    """Retrieves declaration by language.  Attach extern C if needed."""
    lang = self._benchmark.language.lower()
    sig = self._benchmark.function_signature + ';'

    if self._benchmark.needs_extern:
      return 'extern "C" ' + sig

    if lang != 'c++':
      logging.warning('Unsupported decl - Lang: %s Project: %s', lang,
                      self._benchmark.project)

    return sig

  def _get_nested_item(self, element: dict, *path: str) -> Any:
    """Safely retrieve a nested item from a dictionary without
    throwing an error. Logs whenever an item can not be found
    with a given key."""
    nested_item = element

    for key in path:
      next_nested_item = nested_item.get(key, '')
      if not next_nested_item:
        logging.warning('Missing item "%s" in object: %s', key, nested_item)
      nested_item = next_nested_item

    return nested_item

  def _get_source_line(self, item: dict) -> int:
    return int(self._get_nested_item(item, 'source', 'source_line'))

  def _get_source_file(self, item: dict) -> str:
    return self._get_nested_item(item, 'source', 'source_file')

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

    for current_type in types:
      info_list = introspector.query_introspector_type_info(
          self._benchmark.project, current_type)
      if not info_list:
        logging.warning('Could not retrieve info for project: %s type: %s',
                        self._benchmark.project, current_type)
        continue

      for info in info_list:
        include_file = self._get_source_file(info)
        include_file = os.path.normpath(include_file)
        include_base = os.path.basename(include_file)

        # Ensure include_file is a file.
        if not include_base or '.' not in include_base:
          logging.warning('File %s found as a source path for project: %s',
                          include_file, self._benchmark.project)
          continue
        # Ensure it is a header file (suffix starting with .h).
        if include_base.endswith(('.h', '.hxx', '.hpp')):
          logging.warning(
              'File found with unexpected suffix %s for project: %s',
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

    return list(files)

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
    func_sig = self._benchmark.function_signature
    function_source = introspector.query_introspector_function_source(
        project, func_sig)

    if not function_source:
      logging.warning(
          'Could not retrieve function source for project: %s '
          'function_signature: %s', project, func_sig)

    return function_source

  def _get_xrefs_to_function(self) -> list[str]:
    """Queries FI for function being fuzzed."""
    project = self._benchmark.project
    func_sig = self._benchmark.function_signature
    xrefs = introspector.query_introspector_cross_references(project, func_sig)

    if not xrefs:
      logging.warning(
          'Could not retrieve xrefs for project: %s '
          'function_signature: %s', project, func_sig)
    return xrefs

  def get_context_info(self) -> dict:
    """Retrieves contextual information and stores them in a dictionary."""
    xrefs = self._get_xrefs_to_function()
    func_source = self._get_function_implementation()
    files = self._get_files_to_include()
    decl = self._get_embeddable_declaration()
    header = self.get_prefixed_header_file()

    context_info = {
        'xrefs': xrefs,
        'func_source': func_source,
        'files': files,
        'decl': decl,
        'header': header,
    }

    logging.debug('Context: %s', context_info)

    return context_info

  def _concat_info_lines(self, info: dict) -> str:
    """Concatenates source code lines based on |info|."""
    include_file = self._get_source_file(info)
    include_lines = sorted([self._get_source_line(info)] + [
        self._get_source_line(element) for element in info.get('elements', [])
    ])

    # Add the next line after the last element.
    return introspector.query_introspector_source_code(self._benchmark.project,
                                                       include_file,
                                                       include_lines[0],
                                                       include_lines[-1] + 1)

  def get_type_def(self, type_name: str) -> str:
    """Retrieves the source code definitions for the given |type_name|."""
    type_names = [self._clean_type(type_name)]
    considered_types = []
    type_def = ''

    while type_names:
      # Breath-first is more suitable for prompting.
      current_type = type_names.pop(0)
      info_list = introspector.query_introspector_type_info(
          self._benchmark.project, current_type)
      if not info_list:
        logging.warning('Could not type info for project: %s type: %s',
                        self._benchmark.project, current_type)
        continue

      for info in info_list:
        type_def += self._concat_info_lines(info) + '\n'
        considered_types.append(current_type)

        # Retrieve nested unseen types.
        new_type_type = info.get('type')
        new_type_name = info.get('name')
        if (new_type_type and new_type_type in COMPLEX_TYPES and
            new_type_name and new_type_name not in considered_types):
          type_names.append(new_type_name)

    return type_def

  def get_same_header_file_paths(self, wrong_file: str) -> list[str]:
    """Retrieves path of header files with the same name as |wrong_name|."""
    wrong_file_name = os.path.splitext(os.path.basename(wrong_file))
    header_list = introspector.query_introspector_header_files(
        self._benchmark.project)

    candidate_headers = []
    for header in header_list:
      correct_file_name = os.path.splitext(os.path.basename(header))
      if wrong_file_name == correct_file_name:
        candidate_headers.append(header)

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
    return candidate_headers[:5]

  def _get_header_files_to_include(self, func_sig: str) -> Optional[str]:
    """Retrieves the header file of the function signature."""
    header_file = introspector.query_introspector_header_files_to_include(
        self._benchmark.project, func_sig)
    return header_file[0] if header_file else None

  def _get_target_function_file_path(self) -> str:
    """Retrieves the header/source file of the function under test."""
    # Step 1: Find a header file from the default API.
    header_file = self._get_header_files_to_include(
        self._benchmark.function_signature)
    if header_file:
      return header_file

    # Step 2: Find a header file that shares the same name as the source file.
    # TODO: Make this more robust, e.g., when header file and base file do not
    # share the same basename.
    source_file = introspector.query_introspector_source_file_path(
        self._benchmark.project, self._benchmark.function_signature)
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
    include_statement = f'#include "{header_file}"'
    return (f'extern "C" {{\n{include_statement}\n}}'
            if self._benchmark.needs_extern else include_statement)

  def get_prefixed_header_file_by_name(self, func_name: str) -> Optional[str]:
    """Retrieves the header file based on function name with `extern "C"` if
    needed."""
    func_sig = introspector.query_introspector_function_signature(
        self._benchmark.project, func_name)
    return self.get_prefixed_header_file(func_sig)
