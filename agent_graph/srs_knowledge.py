"""
SRS Knowledge representation for stateless iterative analysis.

This module provides a structured representation of API semantic knowledge
that can be incrementally refined without accumulating conversation history.
"""
import json
import re
from typing import Dict, List, Any, Optional


class SRSKnowledge:
    """
    Structured representation of SRS (Software Requirements Specification) knowledge.
    
    This class maintains the semantic understanding of an API function that can be
    incrementally refined through stateless LLM calls. It represents the "state"
    that gets passed between iterations instead of conversation history.
    """
    
    def __init__(self):
        """Initialize empty SRS knowledge structure."""
        self.target_function: str = ""
        self.archetype: Dict[str, Any] = {
            "primary_pattern": "unknown",
            "confidence": "LOW",
            "evidence_count": 0
        }
        self.functional_requirements: List[Dict[str, Any]] = []
        self.preconditions: List[Dict[str, Any]] = []
        self.postconditions: List[Dict[str, Any]] = []
        self.constraints: List[Dict[str, Any]] = []
        self.parameter_strategies: List[Dict[str, Any]] = []
        self.quality_attributes: Dict[str, Any] = {
            "high_confidence_items": [],
            "medium_confidence_items": [],
            "low_confidence_items": [],
            "evidence_quality": "Limited"
        }
        self.metadata: Dict[str, Any] = {
            "must_call_target": "yes",
            "category": "unknown",
            "complexity": "unknown",
            "state_model": "unknown"
        }
        
        # Internal tracking
        self._update_count: int = 0
        self._last_update_iteration: int = -1
        self._convergence_streak: int = 0
    
    @classmethod
    def from_json(cls, json_data: Dict[str, Any]) -> 'SRSKnowledge':
        """
        Create SRSKnowledge from parsed JSON data.
        
        Args:
            json_data: Parsed SRS JSON dictionary
            
        Returns:
            SRSKnowledge instance
        """
        knowledge = cls()
        knowledge.target_function = json_data.get("target_function", "")
        knowledge.archetype = json_data.get("archetype", knowledge.archetype)
        knowledge.functional_requirements = json_data.get("functional_requirements", [])
        knowledge.preconditions = json_data.get("preconditions", [])
        knowledge.postconditions = json_data.get("postconditions", [])
        knowledge.constraints = json_data.get("constraints", [])
        knowledge.parameter_strategies = json_data.get("parameter_strategies", [])
        knowledge.quality_attributes = json_data.get("quality_attributes", knowledge.quality_attributes)
        knowledge.metadata = json_data.get("metadata", knowledge.metadata)
        return knowledge
    
    def to_compact_text(self, max_items_per_section: int = 5) -> str:
        """
        Convert to compact text representation for incremental prompts.
        
        This format is optimized for token efficiency while preserving
        essential information for the LLM to refine.
        
        Args:
            max_items_per_section: Maximum items to show per section
            
        Returns:
            Compact text representation (~1-2K tokens)
        """
        lines = []
        
        # Archetype
        lines.append(f"## Archetype: {self.archetype.get('primary_pattern', 'unknown')}")
        lines.append(f"Confidence: {self.archetype.get('confidence', 'LOW')} "
                    f"(evidence: {self.archetype.get('evidence_count', 0)})")
        lines.append("")
        
        # Preconditions
        if self.preconditions:
            lines.append(f"## Preconditions ({len(self.preconditions)} total, showing top {max_items_per_section}):")
            for i, pre in enumerate(self.preconditions[:max_items_per_section]):
                priority = pre.get('priority', 'UNKNOWN')
                req = pre.get('requirement', 'N/A')
                lines.append(f"- [{priority}] {req}")
            if len(self.preconditions) > max_items_per_section:
                lines.append(f"... and {len(self.preconditions) - max_items_per_section} more")
            lines.append("")
        
        # Postconditions
        if self.postconditions:
            lines.append(f"## Postconditions ({len(self.postconditions)} total):")
            for post in self.postconditions[:max_items_per_section]:
                req = post.get('requirement', 'N/A')
                lines.append(f"- {req}")
            if len(self.postconditions) > max_items_per_section:
                lines.append(f"... and {len(self.postconditions) - max_items_per_section} more")
            lines.append("")
        
        # Constraints
        if self.constraints:
            lines.append(f"## Constraints ({len(self.constraints)} total):")
            for con in self.constraints[:max_items_per_section]:
                con_type = con.get('type', 'unknown')
                req = con.get('requirement', 'N/A')
                lines.append(f"- [{con_type}] {req}")
            if len(self.constraints) > max_items_per_section:
                lines.append(f"... and {len(self.constraints) - max_items_per_section} more")
            lines.append("")
        
        # Parameter strategies summary
        if self.parameter_strategies:
            lines.append(f"## Parameter Strategies ({len(self.parameter_strategies)} params):")
            for ps in self.parameter_strategies[:max_items_per_section]:
                param = ps.get('parameter', 'unknown')
                strategy = ps.get('strategy', 'UNKNOWN')
                lines.append(f"- {param}: {strategy}")
            lines.append("")
        
        # Metadata
        lines.append(f"## Metadata:")
        lines.append(f"- Category: {self.metadata.get('category', 'unknown')}")
        lines.append(f"- Complexity: {self.metadata.get('complexity', 'unknown')}")
        lines.append(f"- State Model: {self.metadata.get('state_model', 'unknown')}")
        
        return "\n".join(lines)
    
    def merge_updates(self, updates: Dict[str, Any], iteration: int) -> bool:
        """
        Merge incremental updates into current knowledge.
        
        This method implements smart merging:
        - Deduplicates based on semantic similarity
        - Updates confidence levels
        - Tracks which iteration provided the update
        
        Args:
            updates: Dictionary containing update fields
            iteration: Current iteration number
            
        Returns:
            True if any changes were made, False otherwise
        """
        changed = False
        
        # Update archetype if provided
        if 'archetype_update' in updates:
            new_archetype = updates['archetype_update']
            if isinstance(new_archetype, dict):
                old_pattern = self.archetype.get('primary_pattern', 'unknown')
                new_pattern = new_archetype.get('primary_pattern', old_pattern)
                
                if new_pattern != old_pattern and new_pattern != 'unchanged':
                    # Archetype pattern changed
                    self.archetype.update(new_archetype)
                    changed = True
                elif new_pattern == old_pattern:
                    # Confirmation increases confidence
                    self.archetype['evidence_count'] = self.archetype.get('evidence_count', 0) + 1
                    changed = True
        
        # Merge new preconditions
        if 'new_preconditions' in updates:
            for pre in updates['new_preconditions']:
                if not self._is_duplicate_item(pre, self.preconditions, 'requirement'):
                    self.preconditions.append(pre)
                    changed = True
        
        # Merge new postconditions
        if 'new_postconditions' in updates:
            for post in updates['new_postconditions']:
                if not self._is_duplicate_item(post, self.postconditions, 'requirement'):
                    self.postconditions.append(post)
                    changed = True
        
        # Merge new constraints
        if 'new_constraints' in updates:
            for con in updates['new_constraints']:
                if not self._is_duplicate_item(con, self.constraints, 'requirement'):
                    self.constraints.append(con)
                    changed = True
        
        # Merge new parameter strategies
        if 'new_parameter_strategies' in updates:
            for ps in updates['new_parameter_strategies']:
                param_name = ps.get('parameter')
                if param_name:
                    # Update or add parameter strategy
                    existing_idx = self._find_parameter_strategy_index(param_name)
                    if existing_idx is not None:
                        self.parameter_strategies[existing_idx] = ps
                    else:
                        self.parameter_strategies.append(ps)
                    changed = True
        
        # Merge functional requirements
        if 'new_functional_requirements' in updates:
            for fr in updates['new_functional_requirements']:
                if not self._is_duplicate_item(fr, self.functional_requirements, 'requirement'):
                    self.functional_requirements.append(fr)
                    changed = True
        
        # Update metadata if provided
        if 'metadata_updates' in updates:
            self.metadata.update(updates['metadata_updates'])
            changed = True
        
        # Update tracking
        if changed:
            self._update_count += 1
            self._last_update_iteration = iteration
            self._convergence_streak = 0
        else:
            self._convergence_streak += 1
        
        return changed
    
    def has_converged(self, threshold: int = 3) -> bool:
        """
        Check if knowledge has converged (no updates for N consecutive iterations).
        
        Args:
            threshold: Number of consecutive iterations without updates
            
        Returns:
            True if converged, False otherwise
        """
        return self._convergence_streak >= threshold
    
    def to_full_json(self) -> Dict[str, Any]:
        """
        Convert to complete SRS JSON format.
        
        Returns:
            Complete SRS JSON dictionary
        """
        return {
            "srs_version": "1.0",
            "target_function": self.target_function,
            "archetype": self.archetype,
            "functional_requirements": self.functional_requirements,
            "preconditions": self.preconditions,
            "postconditions": self.postconditions,
            "constraints": self.constraints,
            "parameter_strategies": self.parameter_strategies,
            "quality_attributes": self.quality_attributes,
            "metadata": self.metadata
        }
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get statistics about current knowledge state.
        
        Returns:
            Dictionary with statistics
        """
        return {
            "total_preconditions": len(self.preconditions),
            "total_postconditions": len(self.postconditions),
            "total_constraints": len(self.constraints),
            "total_parameter_strategies": len(self.parameter_strategies),
            "total_functional_requirements": len(self.functional_requirements),
            "update_count": self._update_count,
            "last_update_iteration": self._last_update_iteration,
            "convergence_streak": self._convergence_streak,
            "archetype_confidence": self.archetype.get('confidence', 'LOW'),
            "evidence_count": self.archetype.get('evidence_count', 0)
        }
    
    def _is_duplicate_item(
        self, 
        new_item: Dict[str, Any], 
        existing_items: List[Dict[str, Any]], 
        key_field: str
    ) -> bool:
        """
        Check if an item is a duplicate based on a key field.
        
        Args:
            new_item: New item to check
            existing_items: List of existing items
            key_field: Field name to compare
            
        Returns:
            True if duplicate found, False otherwise
        """
        if not isinstance(new_item, dict):
            return False
        
        new_value = new_item.get(key_field, "")
        if not new_value:
            return False
        
        new_normalized = new_value.lower().strip()
        
        for item in existing_items:
            if not isinstance(item, dict):
                continue
            existing_value = item.get(key_field, "")
            if not existing_value:
                continue
            existing_normalized = existing_value.lower().strip()
            
            # Simple exact match for now (can be enhanced with semantic similarity)
            if new_normalized == existing_normalized:
                return True
        
        return False
    
    def _find_parameter_strategy_index(self, param_name: str) -> Optional[int]:
        """
        Find the index of a parameter strategy by parameter name.
        
        Args:
            param_name: Parameter name to search for
            
        Returns:
            Index if found, None otherwise
        """
        for i, ps in enumerate(self.parameter_strategies):
            if ps.get('parameter') == param_name:
                return i
        return None


def parse_srs_json_from_response(response: str) -> Optional[Dict[str, Any]]:
    """
    Extract and parse SRS JSON from LLM response.
    
    Args:
        response: LLM response text
        
    Returns:
        Parsed SRS JSON or None if not found/invalid
    """
    import re
    
    try:
        # Look for <srs_json>...</srs_json> tags
        match = re.search(r'<srs_json>\s*(\{.*?\})\s*</srs_json>', response, re.DOTALL)
        if match:
            json_str = match.group(1)
            return json.loads(json_str)
        else:
            # No <srs_json> tags found in response
            return None
    except json.JSONDecodeError as e:
        # Failed to parse SRS JSON
        return None
    except Exception as e:
        # Error extracting SRS JSON
        return None


def parse_incremental_updates_from_response(response: str) -> Dict[str, Any]:
    """
    Parse incremental update JSON from LLM response.
    
    This is used for stateless iteration where the LLM only returns
    what changed, not the full SRS.
    
    Args:
        response: LLM response text
        
    Returns:
        Dictionary with update fields (may be empty)
    """
    import re
    
    updates = {
        "new_preconditions": [],
        "new_postconditions": [],
        "new_constraints": [],
        "new_parameter_strategies": [],
        "new_functional_requirements": [],
        "archetype_update": None,
        "metadata_updates": {}
    }
    
    try:
        # Look for <updates>...</updates> tags
        match = re.search(r'<updates>\s*(\{.*?\})\s*</updates>', response, re.DOTALL)
        if match:
            json_str = match.group(1)
            parsed = json.loads(json_str)
            updates.update(parsed)
            return updates
        else:
            # Fallback: try to parse the entire response as JSON
            try:
                parsed = json.loads(response)
                updates.update(parsed)
                return updates
            except:
                # No structured updates found in response
                return updates
    except json.JSONDecodeError as e:
        # Could not parse incremental updates as JSON
        return updates
    except Exception as e:
        # Error parsing incremental updates
        return updates

