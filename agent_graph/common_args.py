"""Common argument parsing logic for LangGraph fuzzing workflow.

This module provides argument parsing functions for the LangGraph-based
fuzzing workflow. It separates arguments into base arguments (shared across
all interfaces) and LangGraph-specific arguments.

Module Structure:
-----------------
1. _add_base_arguments() [Private]
   - Core benchmark arguments (-y, -f)
   - Prompt and context configuration (-pf, -npf, -afp, --context)
   - Execution parameters (-mr, -to, --delay, -p, --custom-pipeline)
   - Infrastructure configuration (-e, -of, -w, -td, -lo)
   - Benchmark generation (-b, -g, -gp, -gm)
   - Cloud experiment configuration (-c, -cb)
   - Model configuration (-l, -a)

2. add_langgraph_only_arguments() [Public - Main Entry Point]
   - Calls _add_base_arguments()
   - Adds LangGraph LLM parameters (-n, -t, -tr)
   - Used by: agent_graph/main.py

3. add_langgraph_specific_arguments() [Public]
   - LangGraph workflow control (--langgraph-mode, --workflow-config)
   - Human-in-the-loop control (--enable-human-in-loop)
   - Used by: agent_graph/main.py

Usage Example:
--------------
    parser = argparse.ArgumentParser()
    add_langgraph_only_arguments(parser)      # Add base + LLM args
    add_langgraph_specific_arguments(parser)  # Add workflow control args
    args = parser.parse_args()
"""

import argparse
import os
from datetime import datetime
from data_prep import introspector
from llm_toolkit import models

# Constants
RESULTS_DIR = './results'
NUM_ANA = int(os.getenv('LLM_NUM_ANA', '2'))
RUN_TIMEOUT: int = 300
LOG_LEVELS = ['debug', 'info', 'error']


def _add_base_arguments(parser: argparse.ArgumentParser) -> None:
    """Add base arguments shared by all interfaces.
    
    This is a private helper function that contains all the common arguments
    used across different entry points of the fuzzing system.
    """
    
    # Core benchmark arguments
    parser.add_argument('-y',
                        '--benchmark-yaml',
                        type=str,
                        required=False,
                        default='',
                        help='A benchmark YAML file.')
    
    parser.add_argument('-f',
                        '--function-name',
                        type=str,
                        required=False,
                        help='The function name to analyze. If not specified, processes the first function in the YAML.')
    
    # Prompt and context configuration
    parser.add_argument('-pf',
                        '--prompt-file',
                        type=str,
                        default='',
                        help='A file containing the prompt to reconstruct for initial agent.')
    
    parser.add_argument('-npf',
                        '--no-prompt-file',
                        action='store_true',
                        help='Skip using prompt file even if provided.')
    
    parser.add_argument('-afp',
                        '--additional-files-path',
                        type=str,
                        default='',
                        help='The path to a directory containing any additional files needed by the agents under test.')
    
    parser.add_argument('--context',
                        action='store_true',
                        default=False,
                        help='Add context to function under test.')
    
    # Execution parameters
    parser.add_argument('-mr',
                        '--max-round',
                        type=int,
                        default=100,
                        help='Max trial round for agents.')
    
    parser.add_argument('-to', '--run-timeout', type=int, default=RUN_TIMEOUT)
    
    # Infrastructure configuration
    parser.add_argument('-e',
                        '--introspector-endpoint',
                        type=str,
                        default=introspector.DEFAULT_INTROSPECTOR_ENDPOINT)
    
    parser.add_argument('-of',
                        '--oss-fuzz-dir',
                        help='OSS-Fuzz dir path to use. Create temporary directory by default.',
                        default='')
    
    parser.add_argument('-w', '--work-dir', default=RESULTS_DIR)
    
    # Note: LangGraph uses hardcoded prompt paths in agent_graph/prompt_loader.py
    # The -td argument is kept for backward compatibility with legacy workflows
    # but is not used by LangGraph agents
    
    parser.add_argument('-lo',
                        '--log-level',
                        help=f'Sets the logging level. Options available: {", ".join(LOG_LEVELS)}.',
                        default='info')
    
    # Benchmark generation parameters
    parser.add_argument('-b', 
                        '--benchmarks-directory', 
                        type=str,
                        default='',
                        help='Directory containing benchmark YAML files.')
    
    parser.add_argument('-g',
                        '--generate-benchmarks',
                        help=('Generate benchmarks and use those for analysis. This is a string '
                              'of comma-separated heuristics to use when identifying benchmark '
                              'targets. Options available: '
                              f'{", ".join(introspector.get_oracle_dict().keys())}.'),
                        type=str,
                        default='')
    
    parser.add_argument('-gp',
                        '--generate-benchmarks-projects',
                        help='Projects to generate benchmarks for in a comma separated string.',
                        type=str,
                        default='')
    
    parser.add_argument('-gm',
                        '--generate-benchmarks-max',
                        help='Max targets to generate per benchmark heuristic.',
                        type=int,
                        default=5)
    
    # Execution control
    parser.add_argument('--delay',
                        type=int,
                        default=0,
                        help=('Delay each experiment by certain seconds (e.g., 10s) to avoid '
                              'exceeding quota limit in large scale experiments.'))
    
    parser.add_argument('-p',
                        '--prompt-builder',
                        help='The prompt builder to use for harness generation.',
                        default='DEFAULT')
    
    parser.add_argument('--custom-pipeline', 
                        type=str, 
                        default='',
                        help='Custom pipeline configuration.')
    
    # Cloud experiment configuration
    parser.add_argument('-c',
                        '--cloud-experiment-name',
                        type=str,
                        default='',
                        help='The name of the cloud experiment.')
    
    parser.add_argument('-cb',
                        '--cloud-experiment-bucket',
                        type=str,
                        default='',
                        help='A gcloud bucket to store experiment files.')
    
    # Model configuration
    parser.add_argument('-l',
                        '--model',
                        default='vertex_ai_gemini-2-5-pro-chat',
                        help=('Models available: '
                              f'{", ".join(models.LLM.all_llm_names())}.'))
    
    parser.add_argument('-a',
                        '--ai-binary',
                        required=False,
                        nargs='?',
                        const=os.getenv('AI_BINARY', ''),
                        default='',
                        help='Path to AI binary for model execution.')


def add_langgraph_only_arguments(parser: argparse.ArgumentParser) -> None:
    """Add arguments for LangGraph workflow (no pipeline requirement).
    
    This function is the main entry point for argument parsing in the LangGraph
    workflow. It combines base arguments with LangGraph-specific LLM parameters.
    
    Used by: agent_graph/main.py
    """
    # Add all base arguments
    _add_base_arguments(parser)
    
    # Add LangGraph-specific LLM parameters
    parser.add_argument('-n',
                        '--num-samples',
                        type=int,
                        default=1,
                        help='The number of samples to request from LLM.')
    
    parser.add_argument('-t',
                        '--temperature',
                        type=float,
                        default=0.4,
                        help='A value between 0 and 1 representing the variety of the targets generated by LLM.')
    
    parser.add_argument('-tr',
                        '--temperature-list',
                        nargs='*',
                        type=float,
                        default=[],
                        help=('A list of values representing the temperatures will be used by '
                              'each sample LLM query.'))

def add_langgraph_specific_arguments(parser: argparse.ArgumentParser) -> None:
    """Add LangGraph workflow control arguments.
    
    These arguments control advanced LangGraph features like human-in-the-loop,
    workflow configuration, etc.
    
    Used by: agent_graph/main.py
    """
    parser.add_argument('--langgraph-mode',
                        action='store_true',
                        help='Use LangGraph workflow instead of traditional agent pipeline.')
    
    parser.add_argument('--workflow-config',
                        type=str,
                        default='',
                        help='Path to workflow configuration file.')
    
    parser.add_argument('--enable-human-in-loop',
                        action='store_true',
                        help='Enable human-in-the-loop for LangGraph workflow.')
