"""
Unified logging system for LangGraph workflows.
Eliminates duplicate logging and provides clean, structured logs.
"""

import os
import threading
from datetime import datetime
from typing import Optional, Dict, Any, List
from pathlib import Path

import logger

class LangGraphLogger:
    """
    Unified logger for LangGraph workflows that eliminates duplicate logging.
    
    Good taste principles:
    1. One logger per workflow, not per agent
    2. Batch writes to avoid file I/O spam  
    3. Simple directory structure: logs/workflow_id/agent_name/
    4. Only log when explicitly requested, not every interaction
    """
    
    _instances: Dict[str, 'LangGraphLogger'] = {}
    _lock = threading.Lock()
    
    def __init__(self, workflow_id: str, trial: int, base_dir: str = "logs"):
        self.workflow_id = workflow_id
        self.trial = trial
        self.base_dir = Path(base_dir)
        self.log_dir = self.base_dir / f"trial_{trial:02d}"
        
        # Ensure directory exists
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Per-agent log buffers to batch writes
        self._buffers: Dict[str, List[str]] = {}
        self._buffer_lock = threading.Lock()
        
        logger.info(f'LangGraph logger initialized: {self.log_dir}', trial=trial)
    
    @classmethod 
    def get_logger(cls, workflow_id: str, trial: int) -> 'LangGraphLogger':
        """Get or create logger instance for this workflow."""
        key = f"{workflow_id}_{trial}"
        
        with cls._lock:
            if key not in cls._instances:
                cls._instances[key] = cls(workflow_id, trial)
            return cls._instances[key]
    
    def log_interaction(self, agent_name: str, interaction_type: str, 
                       content: str, round_num: int = 1) -> None:
        """
        Log a single LLM interaction.
        
        Args:
            agent_name: Name of the agent (e.g., 'FunctionAnalyzer')
            interaction_type: Type of interaction ('prompt', 'response', 'tool_call')
            content: The actual content to log
            round_num: Round number for this interaction
        """
        if not content or not content.strip():
            return
            
        # Create log entry
        timestamp = datetime.now().strftime("%H:%M:%S")
        entry = (
            f"=== {interaction_type.upper()} ROUND {round_num:02d} [{timestamp}] ===\n"
            f"{content}\n"
            f"{'=' * 60}\n\n"
        )
        
        # Add to buffer
        with self._buffer_lock:
            if agent_name not in self._buffers:
                self._buffers[agent_name] = []
            self._buffers[agent_name].append(entry)
    
    def flush_agent_logs(self, agent_name: str) -> None:
        """Flush all buffered logs for an agent to disk."""
        with self._buffer_lock:
            if agent_name not in self._buffers or not self._buffers[agent_name]:
                return
                
            # Write all buffered entries to a single file
            agent_log_file = self.log_dir / f"{agent_name.lower()}.log"
            
            try:
                with open(agent_log_file, 'a', encoding='utf-8') as f:
                    f.writelines(self._buffers[agent_name])
                
                # Clear the buffer
                self._buffers[agent_name] = []
                
                logger.debug(f'Flushed logs for {agent_name} to {agent_log_file}', 
                           trial=self.trial)
                           
            except Exception as e:
                logger.warning(f'Failed to flush logs for {agent_name}: {e}', 
                             trial=self.trial)
    
    def log_workflow_event(self, event_type: str, message: str, 
                          metadata: Optional[Dict[str, Any]] = None) -> None:
        """Log workflow-level events (state transitions, errors, etc.)"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        workflow_log = self.log_dir / "workflow.log"
        
        try:
            with open(workflow_log, 'a', encoding='utf-8') as f:
                f.write(f"[{timestamp}] {event_type}: {message}\n")
                if metadata:
                    f.write(f"  Metadata: {metadata}\n")
                f.write("\n")
        except Exception as e:
            logger.warning(f'Failed to log workflow event: {e}', trial=self.trial)
    
    def finalize(self) -> None:
        """Flush all remaining logs and clean up."""
        with self._buffer_lock:
            for agent_name in list(self._buffers.keys()):
                self.flush_agent_logs(agent_name)
        
        logger.info(f'LangGraph logger finalized: {self.log_dir}', trial=self.trial)

class LoggingMixin:
    """
    Mixin for agents to use unified logging.
    
    Usage:
    class MyAgent(LoggingMixin, BaseAgent):
        def __init__(self, ...):
            super().__init__(...)
            self.setup_logging("MyAgent")
    """
    
    def setup_logging(self, agent_name: str) -> None:
        """Setup unified logging for this agent."""
        if not hasattr(self, 'trial'):
            raise ValueError("Agent must have 'trial' attribute for logging")
            
        self._langgraph_logger = LangGraphLogger.get_logger(
            workflow_id="fuzzing_workflow", 
            trial=self.trial
        )
        self._agent_name = agent_name
        self._round = 0
    
    def log_llm_prompt(self, prompt: str) -> None:
        """Log LLM prompt using unified logger."""
        if not hasattr(self, '_langgraph_logger'):
            # Fallback to original logging
            logger.info('<PROMPT>%s</PROMPT>', prompt, trial=getattr(self, 'trial', 0))
            return
            
        self._round += 1
        
        # Log to standard logger (for real-time monitoring)
        logger.info('<PROMPT:ROUND %02d>', self._round, trial=self.trial)
        
        # Buffer to unified logger (for file output)
        self._langgraph_logger.log_interaction(
            agent_name=self._agent_name,
            interaction_type='prompt', 
            content=prompt,
            round_num=self._round
        )
    
    def log_llm_response(self, response: str) -> None:
        """Log LLM response using unified logger."""
        if not hasattr(self, '_langgraph_logger'):
            # Fallback to original logging
            logger.info('<RESPONSE>%s</RESPONSE>', response, trial=getattr(self, 'trial', 0))
            return
            
        # Log to standard logger (for real-time monitoring)
        logger.info('<RESPONSE:ROUND %02d>', self._round, trial=self.trial)
        
        # Buffer to unified logger (for file output)
        self._langgraph_logger.log_interaction(
            agent_name=self._agent_name,
            interaction_type='response',
            content=response, 
            round_num=self._round
        )
    
    def finalize_logging(self) -> None:
        """Flush logs when agent completes."""
        if hasattr(self, '_langgraph_logger'):
            self._langgraph_logger.flush_agent_logs(self._agent_name)
