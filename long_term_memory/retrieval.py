"""
Knowledge Retrieval for Long-term Memory

Retrieves archetype patterns, code skeletons, and pitfall guides
for function analysis and driver prototyping.
"""

import os
from pathlib import Path
from typing import Dict, List, Optional


class KnowledgeRetriever:
    """Retrieves knowledge from long-term memory files."""
    
    ARCHETYPES = [
        "stateless_parser",
        "object_lifecycle",
        "state_machine",
        "stream_processor",
        "round_trip",
        "file_based"
    ]
    
    PITFALLS = [
        "initialization_errors",
        "data_argument_errors",
        "call_sequence_errors",
        "resource_management"
    ]
    
    # Mapping: archetype → relevant pitfalls
    ARCHETYPE_PITFALLS = {
        "stateless_parser": ["data_argument_errors"],
        "object_lifecycle": ["initialization_errors", "data_argument_errors", 
                            "call_sequence_errors", "resource_management"],
        "state_machine": ["initialization_errors", "call_sequence_errors", 
                         "resource_management"],
        "stream_processor": ["call_sequence_errors", "resource_management"],
        "round_trip": ["data_argument_errors", "resource_management"],
        "file_based": ["resource_management"]
    }
    
    def __init__(self, base_path: Optional[Path] = None):
        """Initialize retriever with base path."""
        if base_path is None:
            # Default: same directory as this file
            base_path = Path(__file__).parent
        self.base_path = Path(base_path)
        
    def get_archetype(self, archetype_name: str) -> str:
        """Retrieve archetype knowledge document.
        
        Args:
            archetype_name: One of ARCHETYPES
            
        Returns:
            Markdown content describing the archetype
        """
        if archetype_name not in self.ARCHETYPES:
            raise ValueError(f"Unknown archetype: {archetype_name}")
        
        path = self.base_path / "archetypes" / f"{archetype_name}.md"
        return path.read_text()
    
    def get_skeleton(self, archetype_name: str) -> str:
        """Retrieve code skeleton for archetype.
        
        Args:
            archetype_name: One of ARCHETYPES
            
        Returns:
            C/C++ code skeleton
        """
        if archetype_name not in self.ARCHETYPES:
            raise ValueError(f"Unknown archetype: {archetype_name}")
        
        path = self.base_path / "skeletons" / f"{archetype_name}_skeleton.c"
        return path.read_text()
    
    def get_pitfall(self, pitfall_name: str) -> str:
        """Retrieve pitfall guide.
        
        Args:
            pitfall_name: One of PITFALLS
            
        Returns:
            Markdown content describing the pitfall category
        """
        if pitfall_name not in self.PITFALLS:
            raise ValueError(f"Unknown pitfall: {pitfall_name}")
        
        path = self.base_path / "pitfalls" / f"{pitfall_name}.md"
        return path.read_text()
    
    def get_pitfalls(self, pitfall_names: List[str]) -> Dict[str, str]:
        """Retrieve multiple pitfall guides.
        
        Args:
            pitfall_names: List of pitfall names
            
        Returns:
            Dict mapping pitfall_name → content
        """
        return {name: self.get_pitfall(name) for name in pitfall_names}
    
    def get_relevant_pitfalls(self, archetype_name: str) -> Dict[str, str]:
        """Get pitfalls relevant to a specific archetype.
        
        Args:
            archetype_name: One of ARCHETYPES
            
        Returns:
            Dict of relevant pitfalls
        """
        if archetype_name not in self.ARCHETYPES:
            raise ValueError(f"Unknown archetype: {archetype_name}")
        
        relevant = self.ARCHETYPE_PITFALLS.get(archetype_name, [])
        return self.get_pitfalls(relevant)
    
    def get_bundle(self, archetype_name: str) -> Dict[str, any]:
        """Get complete knowledge bundle for an archetype.
        
        Includes archetype doc, skeleton, and relevant pitfalls.
        
        Args:
            archetype_name: One of ARCHETYPES
            
        Returns:
            Dict with keys: 'archetype', 'skeleton', 'pitfalls'
        """
        return {
            'archetype': self.get_archetype(archetype_name),
            'skeleton': self.get_skeleton(archetype_name),
            'pitfalls': self.get_relevant_pitfalls(archetype_name)
        }
    
    def list_archetypes(self) -> List[str]:
        """List all available archetypes."""
        return self.ARCHETYPES.copy()
    
    def list_pitfalls(self) -> List[str]:
        """List all available pitfall categories."""
        return self.PITFALLS.copy()


# Convenience functions for quick access

def get_archetype_bundle(archetype: str) -> Dict[str, any]:
    """Quick access: get full knowledge bundle for archetype."""
    retriever = KnowledgeRetriever()
    return retriever.get_bundle(archetype)


def get_skeleton_code(archetype: str) -> str:
    """Quick access: get just the skeleton code."""
    retriever = KnowledgeRetriever()
    return retriever.get_skeleton(archetype)


def get_pitfall_guide(pitfall: str) -> str:
    """Quick access: get specific pitfall guide."""
    retriever = KnowledgeRetriever()
    return retriever.get_pitfall(pitfall)


# Example usage
if __name__ == "__main__":
    retriever = KnowledgeRetriever()
    
    print("Available archetypes:")
    for arch in retriever.list_archetypes():
        print(f"  - {arch}")
    
    print("\nAvailable pitfalls:")
    for pit in retriever.list_pitfalls():
        print(f"  - {pit}")
    
    print("\n" + "="*60)
    print("Example: Object Lifecycle Bundle")
    print("="*60)
    
    bundle = retriever.get_bundle("object_lifecycle")
    
    print("\n[Archetype Doc Preview]")
    print(bundle['archetype'][:500] + "...\n")
    
    print("[Skeleton Code Preview]")
    print(bundle['skeleton'][:400] + "...\n")
    
    print(f"[Relevant Pitfalls: {list(bundle['pitfalls'].keys())}]")

