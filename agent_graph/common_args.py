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
"""Common argument parsing logic shared between agent_test.py and LangGraph."""

import argparse
import os
from datetime import datetime
from data_prep import introspector
from llm_toolkit import models

# Constants
RESULTS_DIR = f'./results-{datetime.now().strftime("%Y-%m-%d-%H-%M")}'
NUM_ANA = int(os.getenv('LLM_NUM_ANA', '2'))
RUN_TIMEOUT: int = 300


def add_common_arguments(parser: argparse.ArgumentParser) -> None:
    """Add common arguments used by both agent_test.py and LangGraph interface."""
    
    # Core benchmark arguments
    parser.add_argument('-y',
                        '--benchmark-yaml',
                        type=str,
                        required=True,
                        help='A benchmark YAML file.')
    
    parser.add_argument('-f',
                        '--function-name',
                        type=str,
                        required=False,
                        help='The function name to analyze. If not specified, processes the first function in the YAML.')
    
    # Pipeline configuration
    parser.add_argument('-p',
                        '--pipeline',
                        type=str,
                        required=True,
                        help='Comma-separated list of agent names for testing.')
    
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
    """Add core arguments for LangGraph main.py (without pipeline requirement)."""
    
    # Core benchmark arguments
    parser.add_argument('-y',
                        '--benchmark-yaml',
                        type=str,
                        required=True,
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


def add_langgraph_specific_arguments(parser: argparse.ArgumentParser) -> None:
    """Add LangGraph-specific arguments."""
    
    parser.add_argument('--langgraph-mode',
                        action='store_true',
                        help='Use LangGraph workflow instead of traditional agent pipeline.')
    
    parser.add_argument('--workflow-config',
                        type=str,
                        default='',
                        help='Path to workflow configuration file.')
    
    parser.add_argument('--max-iterations',
                        type=int,
                        default=10,
                        help='Maximum iterations for LangGraph workflow.')
    
    parser.add_argument('--enable-human-in-loop',
                        action='store_true',
                        help='Enable human-in-the-loop for LangGraph workflow.')


def create_parser(description: str = "Fuzzing agent test interface") -> argparse.ArgumentParser:
    """Create a parser with all common arguments."""
    parser = argparse.ArgumentParser(description=description)
    add_common_arguments(parser)
    add_langgraph_specific_arguments(parser)
    return parser


def validate_pipeline_args(pipeline_str: str) -> list[str]:
    """Validate and parse pipeline argument."""
    if not pipeline_str:
        raise argparse.ArgumentTypeError(
            'No agents found in the pipeline. Please provide a valid agent list.')
    
    pipeline = [agent.strip() for agent in pipeline_str.split(',')]
    if not pipeline:
        raise argparse.ArgumentTypeError(
            'No agents found in the pipeline. Please provide a valid agent list.')
    
    return pipeline
