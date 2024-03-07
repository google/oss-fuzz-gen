"""Class to retrieve context from introspector for
better prompt generation."""

import os

from data_prep import introspector
from experiment import benchmark as benchmarklib


class ContextRetriever:
  """Class to retrieve context from introspector for
  better prompt generation."""

  def __init__(self, benchmark: benchmarklib.Benchmark):
    """Constructor."""
    self._benchmark = benchmark

  def get_embeddable_declaration(self) -> str:
    """Retrieve declaration by language. Attach extern C to C projects."""
    lang = self._benchmark.language.lower()
    sig = self._benchmark.function_signature

    if lang == 'c++':
      return sig + ';'
    if lang == 'c':
      return 'extern "C" ' + sig + ';'

    print('Unsupported declaration requested')
    return ''

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

  def _get_struct_type(self, info: dict, seen_types: set,
                       types_to_get: set) -> str:
    """Reconstructs type definition from a struct element.
    Also adds newly seen types to recursively collect definitions."""
    # Attempt to recursively retrieve type information for elements
    elements = info['elements']
    file_name = os.path.normpath(info['source']['source_file'])
    begin_line = int(info['source']['source_line'])
    end_line = int(elements[-1]['source']['source_line'])
    curr_line = int(begin_line)

    reconstructed_type = ''
    # The reason we need to iteratively query FI is because
    # we have to parse each individual source line and
    # extract a possible type which we will recursively
    # query the definition for.
    while curr_line <= end_line:
      source_line = introspector.query_introspector_source_code(
          self._benchmark.project, file_name, str(curr_line), str(curr_line))

      curr_line += 1

      if not source_line:
        continue

      reconstructed_type += source_line

      # The first line looks like struct X {
      if curr_line == begin_line:
        continue

      newly_seen_type = self._clean_type(
          self._extract_type_from_source_line(
              source_line, elements[curr_line - begin_line - 1]))
      if not newly_seen_type or newly_seen_type in seen_types:
        continue

      print("Newly seen type: {}".format(newly_seen_type))
      seen_types.add(newly_seen_type)
      types_to_get.add(newly_seen_type)

    return reconstructed_type

  def get_embeddable_types(self) -> list[str]:
    """Retrieve types from FI."""
    seen_types = set()
    types_to_get = set()
    types = set()

    types_to_get.add(self._clean_type(self._benchmark.return_type))

    params = self._benchmark.params

    for param in params:
      cleaned_type = self._clean_type(param['type'])
      if not cleaned_type:
        continue
      types_to_get.add(cleaned_type)

    seen_types = types_to_get

    print("Querying for types: {}".format(types_to_get))

    # Add support for recursively querying for types
    while types_to_get:
      current_type = types_to_get.pop()
      print(f'Querying for type: {current_type}')
      info = introspector.query_introspector_type_info(self._benchmark.project,
                                                       current_type)
      if not info:
        continue

      reconstructed_type = ''
      # For now, info is a single element and not a list.
      # Requested it be changed to a list, so that type
      # elements with the same name will be returned.
      if info['type'] == 'struct':
        reconstructed_type = self._get_struct_type(info, seen_types,
                                                   types_to_get)
      if info['type'] == 'typedef':
        reconstructed_type = self._get_typedef_type(info)

      if reconstructed_type:
        types.add(reconstructed_type)

    return list(types)

  def _extract_type_from_source_line(self, source_line: str,
                                     type_element: dict) -> str:
    """Attempts to extract a type from a source line."""
    # Do so by attempting to match for name and extracting everything before it

    index = source_line.find(type_element['name'])

    if index == -1:
      return ''

    return source_line[:index]

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
      return ''

    return type_tokens[0]

  def get_embeddable_blob(self) -> str:
    """Retrieve both the types and declaration, to be embedded
    into the prompt."""
    types = self.get_embeddable_types()
    decl = self.get_embeddable_declaration()

    blob = '\n'.join(types) + decl
    return blob
