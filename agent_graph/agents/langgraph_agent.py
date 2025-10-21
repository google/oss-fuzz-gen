"""
LangGraph-native agent base class.

This module provides a clean agent interface designed specifically for LangGraph,
without the legacy ADK/session baggage.
"""
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
import argparse

import logger
from llm_toolkit.models import LLM
from agent_graph.state import FuzzingWorkflowState
from agent_graph.memory import get_agent_messages, add_agent_message
from agent_graph.prompt_loader import get_prompt_manager


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
        system_message: str = ""
    ):
        """
        Initialize a LangGraph agent.
        
        Args:
            name: Unique agent name (e.g., "function_analyzer")
            llm: LLM instance
            trial: Trial number
            args: Command line arguments
            system_message: System instruction for this agent
        """
        self.name = name
        self.llm = llm
        self.trial = trial
        self.args = args
        self.system_message = system_message
    
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
        
        # Log the prompt
        logger.info(
            f'<AGENT {self.name} PROMPT>\n{prompt}\n</AGENT {self.name} PROMPT>',
            trial=self.trial
        )
        
        # Call LLM with this agent's messages only
        response = self.llm.chat_with_messages(messages)
        
        # Add assistant response
        add_agent_message(state, self.name, "assistant", response)
        
        # Log the response
        logger.info(
            f'<AGENT {self.name} RESPONSE>\n{response}\n</AGENT {self.name} RESPONSE>',
            trial=self.trial
        )
        
        return response
    
    def ask_llm(self, prompt: str) -> str:
        """
        Ask LLM a one-off question without conversation history.
        
        This is useful for stateless queries that don't need context.
        
        Args:
            prompt: The question/prompt
        
        Returns:
            LLM response
        """
        messages = [{"role": "user", "content": prompt}]
        
        logger.info(
            f'<AGENT {self.name} ONEOFF>\n{prompt}\n</AGENT {self.name} ONEOFF>',
            trial=self.trial
        )
        
        response = self.llm.chat_with_messages(messages)
        
        logger.info(
            f'<AGENT {self.name} ONEOFF RESPONSE>\n{response}\n</AGENT {self.name} ONEOFF RESPONSE>',
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


class LangGraphFunctionAnalyzer(LangGraphAgent):
    """Function analyzer agent for LangGraph."""
    
    def __init__(self, llm: LLM, trial: int, args: argparse.Namespace):
        # Load system prompt from file
        prompt_manager = get_prompt_manager()
        system_message = prompt_manager.get_system_prompt("function_analyzer")
        
        super().__init__(
            name="function_analyzer",
            llm=llm,
            trial=trial,
            args=args,
            system_message=system_message
        )
    
    def execute(self, state: FuzzingWorkflowState) -> Dict[str, Any]:
        """Analyze the target function."""
        benchmark = state["benchmark"]
        
        # Build prompt from template file
        prompt_manager = get_prompt_manager()
        prompt = prompt_manager.build_user_prompt(
            "function_analyzer",
            project_name=benchmark.get('project', 'unknown'),
            function_name=benchmark.get('function_name', 'unknown'),
            function_signature=benchmark.get('function_signature', 'unknown'),
            additional_context=""
        )
        
        # Chat with LLM
        response = self.chat_llm(state, prompt)
        
        # Parse response and create structured output
        # TODO: Add proper parsing logic
        analysis_result = {
            "summary": response[:500],  # First 500 chars as summary
            "raw_analysis": response,
            "analyzed": True
        }
        
        return {
            "function_analysis": analysis_result
        }


class LangGraphPrototyper(LangGraphAgent):
    """Prototyper agent for LangGraph."""
    
    def __init__(self, llm: LLM, trial: int, args: argparse.Namespace):
        # Load system prompt from file
        prompt_manager = get_prompt_manager()
        system_message = prompt_manager.get_system_prompt("prototyper")
        
        super().__init__(
            name="prototyper",
            llm=llm,
            trial=trial,
            args=args,
            system_message=system_message
        )
    
    def execute(self, state: FuzzingWorkflowState) -> Dict[str, Any]:
        """Generate fuzz target code."""
        benchmark = state["benchmark"]
        function_analysis = state.get("function_analysis", {})
        
        # Determine language
        language = benchmark.get('language', 'C++')
        
        # Build prompt from template file
        prompt_manager = get_prompt_manager()
        prompt = prompt_manager.build_user_prompt(
            "prototyper",
            project_name=benchmark.get('project', 'unknown'),
            function_name=benchmark.get('function_name', 'unknown'),
            function_signature=benchmark.get('function_signature', 'unknown'),
            language=language,
            function_analysis=function_analysis.get('raw_analysis', 'No analysis available'),
            additional_context=""
        )
        
        # Chat with LLM (using prototyper's own message history)
        response = self.chat_llm(state, prompt)
        
        # Extract code from response
        # TODO: Add proper code extraction logic
        fuzz_target_code = response
        
        return {
            "fuzz_target_source": fuzz_target_code
        }


class LangGraphEnhancer(LangGraphAgent):
    """Enhancer agent for LangGraph."""
    
    def __init__(self, llm: LLM, trial: int, args: argparse.Namespace):
        # Load system prompt from file
        prompt_manager = get_prompt_manager()
        system_message = prompt_manager.get_system_prompt("enhancer")
        
        super().__init__(
            name="enhancer",
            llm=llm,
            trial=trial,
            args=args,
            system_message=system_message
        )
    
    def execute(self, state: FuzzingWorkflowState) -> Dict[str, Any]:
        """Fix compilation errors."""
        benchmark = state["benchmark"]
        current_code = state.get("fuzz_target_source", "")
        build_errors = state.get("build_errors", [])
        
        # Determine language
        language = benchmark.get('language', 'C++')
        
        # Format build errors
        error_text = "\n".join(build_errors[:10])
        
        # Build prompt from template file
        prompt_manager = get_prompt_manager()
        prompt = prompt_manager.build_user_prompt(
            "enhancer",
            language=language,
            current_code=current_code,
            build_errors=error_text,
            additional_context=""
        )
        
        # Chat with LLM (using enhancer's own message history)
        response = self.chat_llm(state, prompt)
        
        return {
            "fuzz_target_source": response,
            "retry_count": state.get("retry_count", 0) + 1
        }


class LangGraphCrashAnalyzer(LangGraphAgent):
    """Crash analyzer agent for LangGraph."""
    
    def __init__(self, llm: LLM, trial: int, args: argparse.Namespace):
        # Load system prompt from file
        prompt_manager = get_prompt_manager()
        system_message = prompt_manager.get_system_prompt("crash_analyzer")
        
        super().__init__(
            name="crash_analyzer",
            llm=llm,
            trial=trial,
            args=args,
            system_message=system_message
        )
    
    def execute(self, state: FuzzingWorkflowState) -> Dict[str, Any]:
        """Analyze crash information."""
        benchmark = state["benchmark"]
        crash_info = state.get("crash_info", {})
        fuzz_target = state.get("fuzz_target_source", "")
        
        # Determine language
        language = benchmark.get('language', 'C++')
        
        # Build prompt from template file
        prompt_manager = get_prompt_manager()
        prompt = prompt_manager.build_user_prompt(
            "crash_analyzer",
            crash_info=crash_info.get('error_message', 'No error message'),
            stack_trace=crash_info.get('stack_trace', 'No stack trace'),
            language=language,
            fuzz_target_code=fuzz_target[:1000],
            additional_context=""
        )
        
        # Chat with LLM (using crash_analyzer's own message history)
        response = self.chat_llm(state, prompt)
        
        return {
            "crash_analysis": {
                "root_cause": response,
                "severity": "high",
                "analyzed": True
            }
        }

