"""Class to retrieve context from introspector for
better prompt generation."""

from data_prep import introspector
from experiment import benchmark as benchmarklib


class ContextRetriever:
  """Class to retrieve context from introspector for
  better prompt generation."""

  def __init__(self, benchmark: benchmarklib.Benchmark):
    """Constructor."""
    self._benchmark = benchmark

  def get_embeddable_declaration(self):
    """Retrieve declaration by language. Attach extern C to C projects."""
    lang = self._benchmark.language.lower()
    sig = self._benchmark.function_signature

    if lang == 'c++':
      return sig + ';'
    if lang == 'c':
      return 'extern "C" ' + sig + ';'

    print('Unsupported declaration requested')
    return ''

  def get_embeddable_types(self):
    """Retrieve types from FI."""
    params = self._benchmark.params
    for param in params:
      param_type = param['type']
      print(f'Querying for type: {param_type}')
      info = introspector.query_introspector_type_info(self._benchmark.project,
                                                       param_type)
      if info:
        print(f'Information: {info}')
      else:
        print(f'Could not retrieve info for type: {param_type}')

  def get_embeddable_blob(self):
    """Retrieve both the types and declaration, to be embedded
    into the prompt."""
    self.get_embeddable_types()
    self.get_embeddable_declaration()
