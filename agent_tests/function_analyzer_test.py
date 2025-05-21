import argparse

from agent.function_analyzer import FunctionAnalyzer
from experiment import benchmark as benchmarklib
from llm_toolkit import models

RESULTS_DIR = './results'


def parse_args() -> argparse.Namespace: 
  """Parses command line arguments."""   
  parser = argparse.ArgumentParser(
      description='Evaluate the function analyzer agent.')

  parser.add_argument('-y',
                        '--benchmark-yaml',
                        type=str, 
                        required=True,                        
                        help='A benchmark YAML file.')
  
  parser.add_argument('-w', 
                      '--work-dir', 
                      default=RESULTS_DIR)
  
  parser.add_argument('-mr',
                      '--max-round',
                      type=int,
                      default=100,
                      help='Max trial round for agents.')

  args = parser.parse_args()

  return args

if __name__ == "__main__":
    
    model = models.LLM.setup(
        ai_binary='',
        name='vertex_ai_gemini-1-5-chat'
    )


    args = parse_args()

    function_analyzer = FunctionAnalyzer(trial=1, llm=model, args=args)

    benchmarks = benchmarklib.Benchmark.from_yaml(args.benchmark_yaml)

    if len(benchmarks) == 0:
        raise ValueError("No benchmarks found in the YAML file.")
    
    # Initialize the function analyzer with the first benchmark
    function_analyzer.initialize(benchmarks[0])

    # Run the function analyzer
    function_analyzer.execute([])