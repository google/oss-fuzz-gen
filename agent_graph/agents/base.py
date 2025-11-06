"""
LangGraph-native agent base class.

This module provides a clean agent interface designed specifically for LangGraph,
without the legacy ADK/session baggage.
"""
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional
import argparse

import logger
from llm_toolkit.models import LLM
from agent_graph.state import FuzzingWorkflowState
from agent_graph.memory import get_agent_messages, add_agent_message
from agent_graph.logger import LangGraphLogger, NullLogger


class LangGraphAgent(ABC):
    """
    Base class for LangGraph-compatible agents.
    
    Key differences from ADKBaseAgent:
    - No session management (state-based)
    - Agent-specific message history
    - Direct LLM interaction
    - Cleaner interface
    """
    
    def __init__(
        self,
        name: str,
        llm: LLM,
        trial: int,
        args: argparse.Namespace,
        system_message: str = "",
        enable_detailed_logging: bool = True
    ):
        """
        Initialize a LangGraph agent.
        
        Args:
            name: Unique agent name (e.g., "function_analyzer")
            llm: LLM instance
            trial: Trial number
            args: Command line arguments
            system_message: System instruction for this agent
            enable_detailed_logging: If True, log all LLM interactions to files
        """
        self.name = name
        self.llm = llm
        self.trial = trial
        self.args = args
        self.system_message = system_message
        
        # Initialize detailed logging system (uses NullLogger pattern to avoid None checks)
        self.enable_detailed_logging = enable_detailed_logging
        
        # Get base_dir from work_dirs if available
        base_dir = None
        if hasattr(args, 'work_dirs') and args.work_dirs:
            base_dir = str(args.work_dirs.base)
        
        self._langgraph_logger = (
            LangGraphLogger.get_logger(workflow_id="fuzzing_workflow", trial=trial, base_dir=base_dir)
            if enable_detailed_logging
            else NullLogger()
        )
        self._round = 0
    
    def chat_llm(
        self,
        state: FuzzingWorkflowState,
        prompt: str
    ) -> str:
        """
        Chat with LLM using agent-specific message history.
        
        This method:
        1. Gets this agent's message history from state
        2. Adds the new prompt as a user message
        3. Calls LLM with the agent's messages
        4. Adds the response as an assistant message
        5. Trims messages to 50k tokens
        6. Logs interaction to detailed log files
        
        Args:
            state: The workflow state
            prompt: User prompt to send to LLM
        
        Returns:
            LLM response text
        """
        # Get this agent's messages (initializes with system message if first time)
        messages = get_agent_messages(state, self.name, self.system_message)
        
        # Add user prompt
        add_agent_message(state, self.name, "user", prompt)
        
        # Get updated messages for LLM call
        messages = state["agent_messages"][self.name]
        
        # Increment round counter for detailed logging
        self._round += 1
        
        # Log the prompt (both standard and detailed)
        logger.info(
            f'<AGENT {self.name} PROMPT>\n{prompt}\n</AGENT {self.name} PROMPT>',
            trial=self.trial
        )
        
        # Detailed logging: log prompt with metadata
        prompt_metadata = {
                'model': getattr(self.llm, 'model', 'unknown'),
                'temperature': getattr(self.args, 'temperature', None),
                'num_messages': len(messages)
            }
        self._langgraph_logger.log_interaction(
                agent_name=self.name,
                interaction_type='prompt',
                content=prompt,
                round_num=self._round,
                metadata=prompt_metadata
            )
        
        # Call LLM with this agent's messages only
        response = self.llm.chat_with_messages(messages)
        
        # Track token usage
        token_usage = None
        if hasattr(self.llm, 'last_token_usage') and self.llm.last_token_usage:
            from agent_graph.state import update_token_usage
            usage = self.llm.last_token_usage
            token_usage = usage.copy()
            update_token_usage(
                state, 
                self.name,
                usage.get('prompt_tokens', 0),
                usage.get('completion_tokens', 0),
                usage.get('total_tokens', 0)
            )
        
        # Add assistant response
        add_agent_message(state, self.name, "assistant", response)
        
        # Log the response (both standard and detailed)
        logger.info(
            f'<AGENT {self.name} RESPONSE>\n{response}\n</AGENT {self.name} RESPONSE>',
            trial=self.trial
        )
        
        # Detailed logging: log response with metadata
        response_metadata = {
                'model': getattr(self.llm, 'model', 'unknown'),
                'tokens': token_usage
            }
        self._langgraph_logger.log_interaction(
                agent_name=self.name,
                interaction_type='response',
                content=response,
                round_num=self._round,
                metadata=response_metadata
            )
        
        return response
    
    def ask_llm(self, prompt: str, state: Optional[FuzzingWorkflowState] = None) -> str:
        """
        Ask LLM a one-off question without conversation history.
        
        This is useful for stateless queries that don't need context.
        
        Args:
            prompt: The question/prompt
            state: Optional state for tracking token usage
        
        Returns:
            LLM response
        """
        messages = [{"role": "user", "content": prompt}]
        
        # Increment round counter for detailed logging
        self._round += 1
        
        logger.info(
            f'<AGENT {self.name} ONEOFF>\n{prompt}\n</AGENT {self.name} ONEOFF>',
            trial=self.trial
        )
        
        # Detailed logging: log one-off prompt
        if self._langgraph_logger:
            prompt_metadata = {
                'model': getattr(self.llm, 'model', 'unknown'),
                'temperature': getattr(self.args, 'temperature', None),
                'type': 'one-off (no history)'
            }
        self._langgraph_logger.log_interaction(
                agent_name=self.name,
                interaction_type='prompt',
                content=prompt,
                round_num=self._round,
                metadata=prompt_metadata
            )
        
        response = self.llm.chat_with_messages(messages)
        
        # Track token usage if state is provided
        token_usage = None
        if state and hasattr(self.llm, 'last_token_usage') and self.llm.last_token_usage:
            from agent_graph.state import update_token_usage
            usage = self.llm.last_token_usage
            token_usage = usage.copy()
            update_token_usage(
                state, 
                self.name,
                usage.get('prompt_tokens', 0),
                usage.get('completion_tokens', 0),
                usage.get('total_tokens', 0)
            )
        
        # Detailed logging: log one-off response
        if self._langgraph_logger:
            response_metadata = {
                'model': getattr(self.llm, 'model', 'unknown'),
                'tokens': token_usage,
                'type': 'one-off (no history)'
            }
        self._langgraph_logger.log_interaction(
                agent_name=self.name,
                interaction_type='response',
                content=response,
                round_num=self._round,
                metadata=response_metadata
            )
        
        logger.info(
            f'<AGENT {self.name} ONEOFF RESPONSE>\n{response}\n</AGENT {self.name} ONEOFF RESPONSE>',
            trial=self.trial
        )
        
        return response
    
    def call_llm_stateless(
        self, 
        prompt: str, 
        state: Optional[FuzzingWorkflowState] = None,
        log_prefix: str = "STATELESS"
    ) -> str:
        """
        Call LLM without conversation history (stateless).
        
        This method is used for iterative analysis where we manage state explicitly
        rather than relying on LLM conversation history. Each call is independent,
        with only system message + current prompt.
        
        Differences from ask_llm():
        - Includes system message (ask_llm doesn't)
        - Explicitly designed for iterative refinement patterns
        - Better logging for stateless iteration
        
        Args:
            prompt: User prompt (state should be embedded in the prompt)
            state: Optional state for tracking token usage
            log_prefix: Prefix for log messages
        
        Returns:
            LLM response
        """
        # Construct stateless messages: system + user prompt only
        messages = [
            {"role": "system", "content": self.system_message},
            {"role": "user", "content": prompt}
        ]
        
        # Increment round counter for detailed logging
        self._round += 1
        
        logger.debug(
            f'<AGENT {self.name} {log_prefix}>\n{prompt[:500]}...\n</AGENT {self.name} {log_prefix}>',
            trial=self.trial
        )
        
        # Detailed logging: log stateless prompt
        if self._langgraph_logger:
            prompt_metadata = {
                'model': getattr(self.llm, 'model', 'unknown'),
                'temperature': getattr(self.args, 'temperature', None),
                'type': 'stateless (no conversation history)',
                'prompt_length': len(prompt)
            }
            self._langgraph_logger.log_interaction(
                agent_name=self.name,
                interaction_type='prompt',
                content=prompt,
                round_num=self._round,
                metadata=prompt_metadata
            )
        
        # Call LLM
        response = self.llm.chat_with_messages(messages)
        
        # Track token usage if state is provided
        token_usage = None
        if state and hasattr(self.llm, 'last_token_usage') and self.llm.last_token_usage:
            from agent_graph.state import update_token_usage
            usage = self.llm.last_token_usage
            token_usage = usage.copy()
            update_token_usage(
                state, 
                self.name,
                usage.get('prompt_tokens', 0),
                usage.get('completion_tokens', 0),
                usage.get('total_tokens', 0)
            )
        
        # Detailed logging: log stateless response
        if self._langgraph_logger:
            response_metadata = {
                'model': getattr(self.llm, 'model', 'unknown'),
                'tokens': token_usage,
                'type': 'stateless (no conversation history)',
                'response_length': len(response)
            }
            self._langgraph_logger.log_interaction(
                agent_name=self.name,
                interaction_type='response',
                content=response,
                round_num=self._round,
                metadata=response_metadata
            )
        
        logger.debug(
            f'<AGENT {self.name} {log_prefix} RESPONSE>\n{response[:500]}...\n</AGENT {self.name} {log_prefix} RESPONSE>',
            trial=self.trial
        )
        
        return response
    
    @abstractmethod
    def execute(self, state: FuzzingWorkflowState) -> Dict[str, Any]:
        """
        Execute the agent's main logic.
        
        Args:
            state: Current workflow state
        
        Returns:
            Dictionary of state updates
        """
        pass

