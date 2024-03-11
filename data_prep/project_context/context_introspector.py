"""Class to retrieve context from introspector for
better prompt generation."""

import logging
import os
from typing import Any, Optional

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

  def _get_typedef_type(self, info: dict) -> str:
    """Reconstructs type definition for a typedef element.
    Simply queries for a single line in source code."""
    file_name = os.path.normpath(info['source']['source_file'])
    typedef_line = info['source']['source_line']
    source_line = introspector.query_introspector_source_code(
        self._benchmark.project, file_name, typedef_line, typedef_line)
    # Check to ensure typedef is within the source line.
    # There are instances where it isn't.
    # One example, is when it is combined with a struct declaration
    # 1. typedef X {
    # 2.   T elem1;
    # 3. } X;
    # The typedef element has value 3. In this case,
    # it would be better to ignore the string.
    if 'typedef' not in source_line:
      return ''

    return source_line

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

  def _get_struct_type(self,
                       info: dict,
                       seen_types: set,
                       types_to_get: set,
                       typedef_info: Optional[dict] = None) -> str:
    """Reconstructs type definition from a struct element.
    Also adds newly seen types to recursively collect definitions."""
    file_name = os.path.normpath(
        self._get_nested_item(info, 'source', 'source_file'))
    begin_line = int(self._get_nested_item(info, 'source', 'source_line'))

    elements = self._get_nested_item(info, 'elements')
    # Check to ensure amount of elements in struct is > 0.
    # If it isn't, there is something wrong. Log and return.
    if len(elements) == 0:
      logging.error('Struct type with no elements: %s', info)
      return ''
    begin_line_elem = self._get_source_line(elements[0])
    end_line_elem = int(
        self._get_nested_item(elements[-1], 'source', 'source_line'))

    typedef_line = 0
    if typedef_info:
      typedef_line = int(
          self._get_nested_item(typedef_info, 'source', 'source_line'))

    reconstructed_type = ''
    source_line = ''

    # Attempt to recursively retrieve type information for elements.
    # The reason we need to iteratively query FI is because
    # we have to parse each individual source line and
    # extract a possible type which we will recursively
    # query the definition for.
    for curr_line in range(begin_line, begin_line_elem):
      source_line = introspector.query_introspector_source_code(
          self._benchmark.project, file_name, curr_line, curr_line)
      reconstructed_type += source_line

    for curr_line in range(begin_line_elem, end_line_elem + 1):
      source_line = introspector.query_introspector_source_code(
          self._benchmark.project, file_name, curr_line, curr_line)
      reconstructed_type += source_line

      possible_new_type = self._clean_type(
          self._extract_type_from_source_line(
              source_line, elements[curr_line - begin_line_elem]))

      # Do this check to prevent redundantly adding the same type
      # to types_to_get if the definition has been previously seen
      # or extracted.
      if possible_new_type and possible_new_type not in seen_types:
        seen_types.add(possible_new_type)
        types_to_get.add(possible_new_type)

    # If a typedef element is specified, then we are querying for a
    # typedef + struct combination. The typedef line appears to
    # always be at the end.
    for curr_line in range(end_line_elem + 1, typedef_line):
      source_line = introspector.query_introspector_source_code(
          self._benchmark.project, file_name, curr_line, curr_line)
      reconstructed_type += source_line

    # If we do not see a '}' in the final element's source line
    # Then we can add it ourselves. This would cause problems
    # when typedef and struct definitions are combined.
    # The alternative is to query for source code lines until a '}' is found.
    if '}' not in source_line and not typedef_info:
      reconstructed_type += '};\n'

    return reconstructed_type

  def _clean_info_list(self, info_list: list[dict]) -> list[dict]:
    """Clean out any bugged out values received from type-info."""
    # Currently...
    # * Remove any struct objects with no elements.
    # * Remove duplicates.
    cleaned = []
    for info in info_list:
      if info in cleaned:
        continue
      if self._get_nested_item(
          info,
          'type') == 'struct' and not self._get_nested_item(info, 'elements'):
        continue
      cleaned.append(info)

    return cleaned

  def _is_typedef_and_struct_combined(self, info_list: list[dict]) -> bool:
    """ Determines if the typedef and struct definitions are combined."""
    # There should only be two elements
    if len(info_list) != 2:
      return False

    # If a typedef and struct are combined, the typedef succeeds the struct.
    struct_info = info_list[0]
    typedef_info = info_list[1]

    # They should have type 'struct' and type 'typedef'
    if self._get_nested_item(struct_info,
                             'type') != 'struct' or self._get_nested_item(
                                 typedef_info, 'type') != 'typedef':
      return False

    # They should be in the same file
    struct_file = os.path.normpath(
        self._get_nested_item(struct_info, 'source', 'source_file'))
    typedef_file = os.path.normpath(
        self._get_nested_item(typedef_info, 'source', 'source_file'))
    if struct_file != typedef_file:
      return False

    is_combined = False
    elements = self._get_nested_item(struct_info, 'elements')
    last_element_line = int(
        self._get_nested_item(elements[-1], 'source', 'source_line'))
    typedef_line = int(
        self._get_nested_item(typedef_info, 'source', 'source_line'))
    # Use a heuristic to determine whether or not the elements are combined
    # I.e. They look like this:
    # typedef struct X {...} X;
    #
    # Heuristic goes like this:
    # typedef line and last defined element line in
    # rough proximity of each other.
    #
    # The value is arbitrary. Technically there can be an unbounded
    # amount of lines
    # between the typedef line and last defined element
    # (empty lines, comments) etc.
    if typedef_line - last_element_line <= 3:
      is_combined = True

    return is_combined

  def _get_embeddable_types(self) -> list[str]:
    """Retrieves types from FI."""
    seen_types = set()
    types_to_get = set()
    types = set()

    types_to_get.add(self._clean_type(self._benchmark.return_type))

    params = self._benchmark.params

    for param in params:
      cleaned_type = self._clean_type(param['type'])
      if cleaned_type:
        types_to_get.add(cleaned_type)

    seen_types = types_to_get.copy()

    # Add support for recursively querying for types
    iteration = 0
    while types_to_get:
      iteration += 1
      current_type = types_to_get.pop()
      logging.warning('Querying for type: %s', current_type)
      info_list = introspector.query_introspector_type_info(
          self._benchmark.project, current_type)
      if not info_list:
        continue

      logging.warning('Retrieved %d items for type: %s', len(info_list),
                      current_type)
      info_list = self._clean_info_list(info_list)
      logging.warning('Cleaned list contains %d items', len(info_list))

      reconstructed_type = ''
      # Separately account for `typedef struct X {..} X;` as it is common.
      if self._is_typedef_and_struct_combined(info_list):
        reconstructed_type = self._get_struct_type(info_list[0], seen_types,
                                                   types_to_get, info_list[1])
      else:
        # If the type is not a struct + typedef type, then iterate
        # through the items.
        # Support for enums is coming.
        for info in info_list:
          if info['type'] == 'struct':
            reconstructed_type += self._get_struct_type(info, seen_types,
                                                        types_to_get)
          if info['type'] == 'typedef':
            reconstructed_type += self._get_typedef_type(info)

      if reconstructed_type:
        logging.warning('Reconstructed type %s -> %s', current_type,
                        reconstructed_type)
        types.add(reconstructed_type)
      else:
        logging.warning('Could not reconstruct type for %s', current_type)

    return list(types)

  def _extract_type_from_source_line(self, source_line: str,
                                     type_element: dict) -> str:
    """Attempts to extract a type from a source line.
    Do so by attempting to match for name and extracting
    everything before it."""
    start = next(i for i, c in enumerate(source_line) if str.isalpha(c))
    end = source_line.find(type_element['name'])

    if end == -1:
      return ''

    return source_line[start:end]

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
          'Could not retrieve function source for project: %s '
          'function_signature: %s', project, func_sig)
    return xrefs

  def get_embeddable_blob(self) -> str:
    """Retrieves both the types and declaration, to be embedded
    into the prompt."""
    types = self._get_embeddable_types()
    decl = self._get_embeddable_declaration()

    blob = '\n'.join(types) + decl
    return blob

  def get_other_context(self,
                        get_xrefs: bool = True,
                        get_func_source: bool = True) -> str:
    """Retrieves other context exposed by FI. These currently
    include cross-references and the source of the function being tested."""
    blob = ''

    xrefs = []
    if get_xrefs:
      xrefs = self._get_xrefs_to_function()

    func_source = ''
    if get_func_source:
      func_source = self._get_function_implementation()

    blob = '\n'.join(xrefs) + '\n' + func_source
    return blob
