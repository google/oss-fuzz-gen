"""Class to retrieve context from introspector for
better prompt generation."""

import logging
import os
from typing import Any

from data_prep import introspector
from experiment import benchmark as benchmarklib


class ContextRetriever:
  """Class to retrieve context from introspector for
  better prompt generation."""

  def __init__(self, benchmark: benchmarklib.Benchmark):
    """Constructor."""
    self._benchmark = benchmark

  def _get_embeddable_declaration(self) -> str:
    """Retrieves declaration by language. Attach extern C to C projects."""
    lang = self._benchmark.language.lower()
    sig = self._benchmark.function_signature + ';'

    if lang == 'c':
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

    if 'struct' in type_tokens:
      type_tokens.remove('struct')

    if 'enum' in type_tokens:
      type_tokens.remove('enum')

    if 'const' in type_tokens:
      type_tokens.remove('const')

    if 'volatile' in type_tokens:
      type_tokens.remove('volatile')

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

    # At times, xrefs can be noisy (multiple 100s of loc).
    # Truncate them by default
    xrefs = self._truncate_xrefs(xrefs)
    return xrefs

  def _truncate_xrefs(self, xrefs: list[str]) -> list[str]:
    """Truncates xrefs to 10 lines before and after the 
    function name is referenced."""
    truncated = []
    for xref in xrefs:
      lines = xref.split('\n')
      line_index = -1
      start = 0
      end = len(lines) - 1
      for index, line in enumerate(lines):
        if self._benchmark.function_name in line:
          line_index = index
          break
      # If name was not found, then just return the entire function.
      # If it was, truncate it.
      if line_index != -1:
        start = start if line_index <= 10 else line_index - 10
        end = end if line_index >= end - 10 else line_index + 10
      truncated.append('\n'.join(lines[start:end]))

    return truncated

  def get_context_info(self) -> dict:
    """Retrieves contextual information and stores them in a dictionary."""
    xrefs = self._get_xrefs_to_function()
    func_source = self._get_function_implementation()
    files = self._get_files_to_include()
    decl = self._get_embeddable_declaration()

    context_info = {
        'xrefs': xrefs,
        'func_source': func_source,
        'files': files,
        'decl': decl
    }

    logging.debug('Context: %s', context_info)

    return context_info
