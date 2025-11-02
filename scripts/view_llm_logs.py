#!/usr/bin/env python3
"""
View and analyze LLM interaction logs from LangGraph agents.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional
from collections import defaultdict


def find_log_directories(base_path: Optional[Path] = None) -> List[Path]:
    """
    Find all log directories to search.
    
    Args:
        base_path: Optional base path. Can be:
            - An output directory (e.g., results/output-xxx) - will use output-xxx/logs/
            - A logs directory directly (e.g., results/output-xxx/logs/)
            - None - will search all results/output-*/ directories
    
    Returns:
        List of log directory paths
    """
    if base_path:
        # Check if it's already a logs directory
        if base_path.name == 'logs' and base_path.is_dir():
            return [base_path]
        
        # Check if it has a logs subdirectory
        logs_subdir = base_path / 'logs'
        if logs_subdir.is_dir():
            return [logs_subdir]
        
        # Otherwise treat it as a logs directory itself
        if base_path.is_dir():
            return [base_path]
        
        return []
    
    # No base_path provided - search all output directories
    results_dir = Path('results')
    if not results_dir.exists():
        return []
    
    log_dirs = []
    for output_dir in sorted(results_dir.glob('output-*')):
        if output_dir.is_dir():
            logs_dir = output_dir / 'logs'
            if logs_dir.is_dir():
                log_dirs.append(logs_dir)
    
    return log_dirs


def list_trials(log_dir: Path) -> List[str]:
    """List all available trial directories."""
    trials = []
    for trial_dir in sorted(log_dir.glob("trial_*")):
        if trial_dir.is_dir():
            trials.append(trial_dir.name)
    return trials


def list_agents(trial_dir: Path) -> Dict[str, Dict[str, Path]]:
    """List all agents and their log files in a trial."""
    agents = {}
    for log_file in sorted(trial_dir.glob("*.log")):
        agent_name = log_file.stem
        agents[agent_name] = {"text": log_file}
    
    for json_file in sorted(trial_dir.glob("*.jsonl")):
        agent_name = json_file.stem
        if agent_name in agents:
            agents[agent_name]["json"] = json_file
    
    return agents


def print_text_log(log_file: Path, max_lines: Optional[int] = None):
    """Print text log file."""
    print(f"\n{'=' * 80}")
    print(f"TEXT LOG: {log_file}")
    print(f"{'=' * 80}\n")
    
    with open(log_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()
        
        if max_lines and len(lines) > max_lines:
            print(f"[Showing first {max_lines} lines of {len(lines)} total]\n")
            lines = lines[:max_lines]
        
        for line in lines:
            print(line, end='')
    
    print(f"\n{'=' * 80}\n")


def parse_json_log(json_file: Path) -> List[Dict[str, Any]]:
    """Parse JSONL log file."""
    entries = []
    with open(json_file, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError as e:
                    print(f"Warning: Failed to parse line: {e}", file=sys.stderr)
    return entries


def print_json_summary(entries: List[Dict[str, Any]]):
    """Print summary of JSON log entries."""
    print(f"\n{'=' * 80}")
    print(f"JSON LOG SUMMARY")
    print(f"{'=' * 80}\n")
    
    print(f"Total interactions: {len(entries)}")
    
    # Count by type
    type_counts = defaultdict(int)
    for entry in entries:
        type_counts[entry.get('type', 'unknown')] += 1
    
    print("\nBy type:")
    for interaction_type, count in sorted(type_counts.items()):
        print(f"  {interaction_type}: {count}")
    
    # Token statistics
    total_prompt_tokens = 0
    total_completion_tokens = 0
    total_tokens = 0
    token_entries = 0
    
    for entry in entries:
        metadata = entry.get('metadata', {})
        tokens = metadata.get('tokens')
        if tokens:
            total_prompt_tokens += tokens.get('prompt_tokens', 0)
            total_completion_tokens += tokens.get('completion_tokens', 0)
            total_tokens += tokens.get('total_tokens', 0)
            token_entries += 1
    
    if token_entries > 0:
        print(f"\nToken usage ({token_entries} entries with tokens):")
        print(f"  Prompt tokens:     {total_prompt_tokens:,}")
        print(f"  Completion tokens: {total_completion_tokens:,}")
        print(f"  Total tokens:      {total_tokens:,}")
        print(f"  Average per call:  {total_tokens // token_entries:,}")
    
    print(f"\n{'=' * 80}\n")


def print_interaction(entry: Dict[str, Any], show_metadata: bool = True, truncate: int = 0):
    """Print a single interaction entry."""
    print(f"\n--- {entry.get('type', 'unknown').upper()} ROUND {entry.get('round', 0):02d} [{entry.get('timestamp', 'unknown')}] ---")
    
    if show_metadata and entry.get('metadata'):
        metadata = entry['metadata']
        print(f"Metadata: ", end='')
        # Print compact metadata
        meta_parts = []
        if 'model' in metadata:
            meta_parts.append(f"model={metadata['model']}")
        if 'temperature' in metadata:
            meta_parts.append(f"temp={metadata['temperature']}")
        if 'tokens' in metadata:
            tokens = metadata['tokens']
            meta_parts.append(f"tokens={tokens.get('total_tokens', 0)}")
        print(", ".join(meta_parts))
    
    content = entry.get('content', '')
    if truncate > 0 and len(content) > truncate:
        print(f"\n{content[:truncate]}")
        print(f"\n... [truncated {len(content) - truncate} chars] ...")
    else:
        print(f"\n{content}")
    
    print(f"\n{'-' * 80}")


def view_agent_logs(log_dir: Path, trial: str, agent: str, 
                   format_type: str = 'text', max_lines: Optional[int] = None,
                   show_metadata: bool = True, truncate: int = 0):
    """View logs for a specific agent."""
    trial_dir = log_dir / trial
    if not trial_dir.exists():
        print(f"Error: Trial directory not found: {trial_dir}", file=sys.stderr)
        return 1
    
    agents = list_agents(trial_dir)
    if agent not in agents:
        print(f"Error: Agent '{agent}' not found in {trial}", file=sys.stderr)
        print(f"Available agents: {', '.join(agents.keys())}", file=sys.stderr)
        return 1
    
    agent_files = agents[agent]
    
    if format_type == 'text':
        if 'text' in agent_files:
            print_text_log(agent_files['text'], max_lines)
        else:
            print(f"No text log found for {agent}", file=sys.stderr)
            return 1
    
    elif format_type == 'json':
        if 'json' in agent_files:
            entries = parse_json_log(agent_files['json'])
            print_json_summary(entries)
            
            # Print individual interactions
            for entry in entries:
                print_interaction(entry, show_metadata=show_metadata, truncate=truncate)
        else:
            print(f"No JSON log found for {agent}", file=sys.stderr)
            return 1
    
    elif format_type == 'summary':
        if 'json' in agent_files:
            entries = parse_json_log(agent_files['json'])
            print_json_summary(entries)
        elif 'text' in agent_files:
            # Fallback to basic file info
            log_file = agent_files['text']
            with open(log_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            print(f"\nText log: {log_file}")
            print(f"Total lines: {len(lines)}")
        else:
            print(f"No logs found for {agent}", file=sys.stderr)
            return 1
    
    return 0


def view_token_stats(log_dir: Path, trial: Optional[str] = None):
    """View token usage statistics."""
    if trial:
        trial_dir = log_dir / trial
        stats_file = trial_dir / "token_stats.json"
        
        if not stats_file.exists():
            print(f"No token stats found for {trial}", file=sys.stderr)
            return 1
        
        with open(stats_file, 'r', encoding='utf-8') as f:
            stats = json.load(f)
        
        print(f"\n{'=' * 80}")
        print(f"TOKEN STATISTICS - {trial}")
        print(f"{'=' * 80}\n")
        
        total_prompt = 0
        total_completion = 0
        total_tokens = 0
        total_calls = 0
        
        for agent_name, agent_stats in sorted(stats.items()):
            print(f"\n{agent_name}:")
            print(f"  Calls:             {agent_stats.get('num_calls', 0)}")
            print(f"  Prompt tokens:     {agent_stats.get('prompt_tokens', 0):,}")
            print(f"  Completion tokens: {agent_stats.get('completion_tokens', 0):,}")
            print(f"  Total tokens:      {agent_stats.get('total_tokens', 0):,}")
            
            total_prompt += agent_stats.get('prompt_tokens', 0)
            total_completion += agent_stats.get('completion_tokens', 0)
            total_tokens += agent_stats.get('total_tokens', 0)
            total_calls += agent_stats.get('num_calls', 0)
        
        print(f"\n{'-' * 80}")
        print(f"TOTAL:")
        print(f"  Calls:             {total_calls}")
        print(f"  Prompt tokens:     {total_prompt:,}")
        print(f"  Completion tokens: {total_completion:,}")
        print(f"  Total tokens:      {total_tokens:,}")
        
        if total_calls > 0:
            print(f"  Average per call:  {total_tokens // total_calls:,}")
        
        print(f"\n{'=' * 80}\n")
    
    else:
        # Show stats for all trials
        trials = list_trials(log_dir)
        if not trials:
            print(f"No trials found in {log_dir}", file=sys.stderr)
            return 1
        
        print(f"\n{'=' * 80}")
        print(f"TOKEN STATISTICS - ALL TRIALS")
        print(f"{'=' * 80}\n")
        
        for trial_name in trials:
            trial_dir = log_dir / trial_name
            stats_file = trial_dir / "token_stats.json"
            
            if stats_file.exists():
                with open(stats_file, 'r', encoding='utf-8') as f:
                    stats = json.load(f)
                
                total_tokens = sum(agent_stats.get('total_tokens', 0) 
                                  for agent_stats in stats.values())
                total_calls = sum(agent_stats.get('num_calls', 0) 
                                 for agent_stats in stats.values())
                
                print(f"{trial_name}:")
                print(f"  Total tokens: {total_tokens:,}")
                print(f"  Total calls:  {total_calls}")
                if total_calls > 0:
                    print(f"  Avg/call:     {total_tokens // total_calls:,}")
                print()
        
        print(f"{'=' * 80}\n")
    
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="View and analyze LLM interaction logs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # List all trials
  %(prog)s list

  # View text log for function_analyzer in trial_01
  %(prog)s view trial_01 function_analyzer

  # View JSON log with metadata
  %(prog)s view trial_01 function_analyzer --format json

  # View summary only
  %(prog)s view trial_01 function_analyzer --format summary

  # View token statistics
  %(prog)s tokens trial_01
  %(prog)s tokens  # All trials
        """
    )
    
    parser.add_argument(
        '--log-dir',
        type=Path,
        default=None,
        help='Base directory for logs. Can be either:\n'
             '  - An output directory (e.g., results/output-xxx) - will look in output-xxx/logs/\n'
             '  - A logs directory directly (e.g., results/output-xxx/logs/)\n'
             '  - If not specified, will search in all results/output-*/ directories'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # List command
    list_parser = subparsers.add_parser('list', help='List available trials and agents')
    list_parser.add_argument('trial', nargs='?', help='Specific trial to list agents for')
    
    # View command
    view_parser = subparsers.add_parser('view', help='View logs for a specific agent')
    view_parser.add_argument('trial', help='Trial name (e.g., trial_01)')
    view_parser.add_argument('agent', help='Agent name (e.g., function_analyzer)')
    view_parser.add_argument(
        '--format',
        choices=['text', 'json', 'summary'],
        default='text',
        help='Log format to view'
    )
    view_parser.add_argument(
        '--max-lines',
        type=int,
        help='Maximum lines to show (text format only)'
    )
    view_parser.add_argument(
        '--no-metadata',
        action='store_true',
        help='Hide metadata in JSON format'
    )
    view_parser.add_argument(
        '--truncate',
        type=int,
        default=0,
        help='Truncate content to N characters (0=no truncate)'
    )
    
    # Tokens command
    tokens_parser = subparsers.add_parser('tokens', help='View token usage statistics')
    tokens_parser.add_argument('trial', nargs='?', help='Specific trial (or all if omitted)')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    # Find log directories
    log_dirs = find_log_directories(args.log_dir)
    if not log_dirs:
        if args.log_dir:
            print(f"Error: No log directories found in: {args.log_dir}", file=sys.stderr)
        else:
            print(f"Error: No log directories found in results/output-*/ directories", file=sys.stderr)
        return 1
    
    if args.command == 'list':
        if args.trial:
            # List agents for specific trial across all log directories
            found = False
            for log_dir in log_dirs:
                trial_dir = log_dir / args.trial
                if trial_dir.exists():
                    agents = list_agents(trial_dir)
                    if agents:
                        print(f"\nAgents in {args.trial} ({log_dir}):")
                        for agent_name, files in sorted(agents.items()):
                            file_types = []
                            if 'text' in files:
                                file_types.append('text')
                            if 'json' in files:
                                file_types.append('json')
                            print(f"  {agent_name} ({', '.join(file_types)})")
                        print()
                        found = True
            
            if not found:
                print(f"Error: Trial not found: {args.trial}", file=sys.stderr)
                return 1
        else:
            # List all trials across all log directories
            print(f"\nAvailable trials:")
            for log_dir in log_dirs:
                trials = list_trials(log_dir)
                if trials:
                    print(f"\n  In {log_dir}:")
                    for trial_name in trials:
                        trial_dir = log_dir / trial_name
                        agents = list_agents(trial_dir)
                        print(f"    {trial_name} ({len(agents)} agents)")
            print()
        
        return 0
    
    elif args.command == 'view':
        # Find the log directory containing the specified trial
        for log_dir in log_dirs:
            trial_dir = log_dir / args.trial
            if trial_dir.exists():
                return view_agent_logs(
                    log_dir,
                    args.trial,
                    args.agent,
                    format_type=args.format,
                    max_lines=args.max_lines,
                    show_metadata=not args.no_metadata,
                    truncate=args.truncate
                )
        
        print(f"Error: Trial not found: {args.trial}", file=sys.stderr)
        return 1
    
    elif args.command == 'tokens':
        # Show token stats for all matching log directories
        found = False
        for log_dir in log_dirs:
            if args.trial:
                trial_dir = log_dir / args.trial
                if trial_dir.exists():
                    print(f"\nToken stats for {args.trial} in {log_dir}:")
                    view_token_stats(log_dir, args.trial)
                    found = True
            else:
                trials = list_trials(log_dir)
                if trials:
                    print(f"\nToken stats in {log_dir}:")
                    view_token_stats(log_dir, None)
                    found = True
        
        if not found:
            if args.trial:
                print(f"Error: Trial not found: {args.trial}", file=sys.stderr)
            else:
                print(f"Error: No trials found", file=sys.stderr)
            return 1
        
        return 0
    
    return 0


if __name__ == '__main__':
    sys.exit(main())

