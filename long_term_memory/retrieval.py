"""
Knowledge Retrieval for Long-term Memory

Retrieves archetype patterns from unified SRS JSON files.
Each archetype file contains pattern description, functional requirements,
constraints, parameter strategies, and common pitfalls.
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Any


class KnowledgeRetriever:
    """Retrieves knowledge from unified SRS JSON files."""
    
    ARCHETYPES = [
        "simple_function_call",
        "object_lifecycle",
        "file_path_api",
        "callback_api",
        "streaming_api",
        "multi_parameter_api",
        "exception_handling_api",
        "global_initialization",
        "round_trip",
        "stateful_fuzzing"
    ]
    
    def __init__(self, base_path: Optional[Path] = None):
        """Initialize retriever with base path."""
        if base_path is None:
            # Default: same directory as this file
            base_path = Path(__file__).parent
        self.base_path = Path(base_path)
    
    def _load_srs(self, archetype_name: str) -> Dict[str, Any]:
        """Load SRS JSON file for archetype.
        
        Args:
            archetype_name: One of ARCHETYPES
            
        Returns:
            Parsed SRS JSON as dict
        """
        if archetype_name not in self.ARCHETYPES:
            raise ValueError(f"Unknown archetype: {archetype_name}")
        
        path = self.base_path / "archetypes" / f"{archetype_name}.srs.json"
        if not path.exists():
            raise FileNotFoundError(f"SRS file not found: {path}")
        
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def get_archetype(self, archetype_name: str) -> str:
        """Retrieve archetype knowledge as formatted text.
        
        Args:
            archetype_name: One of ARCHETYPES
            
        Returns:
            Formatted text describing the archetype (backward compatible)
        """
        srs = self._load_srs(archetype_name)
        
        # Format as markdown-like text for backward compatibility
        lines = [
            f"# {srs.get('archetype_name', archetype_name).replace('_', ' ').title()}",
            "",
            f"## API Pattern",
            srs.get('api_pattern', ''),
            "",
            f"## When to Use",
        ]
        for use_case in srs.get('when_to_use', []):
            lines.append(f"- {use_case}")
        
        lines.extend([
            "",
            "## Real Examples",
        ])
        for example in srs.get('real_examples', []):
            lines.append(f"- {example}")
        
        return '\n'.join(lines)
    
    def get_skeleton(self, archetype_name: str, language: str = "c") -> str:
        """Retrieve code skeleton from core_template.
        
        Args:
            archetype_name: One of ARCHETYPES
            language: "c" or "cpp"
            
        Returns:
            C/C++ code skeleton from core_template
        """
        srs = self._load_srs(archetype_name)
        
        # Get template from core_template
        core_template = srs.get('core_template', {})
        template = core_template.get(language, '')
        
        if not template:
            # Fallback to C++ if C not available
            template = core_template.get('cpp', '')
        
        if not template:
            # Fallback: construct from api_pattern
            return f"// {srs.get('api_pattern', '')}\n\nint LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{\n  // TODO: Implement based on {archetype_name}\n  return 0;\n}}"
        
        return template
    
    def get_srs(self, archetype_name: str) -> Dict[str, Any]:
        """Retrieve full SRS JSON for archetype.
        
        Args:
            archetype_name: One of ARCHETYPES
            
        Returns:
            Complete SRS JSON as dict
        """
        return self._load_srs(archetype_name)
    
    def get_pitfalls(self, archetype_name: str) -> Dict[str, str]:
        """Get critical mistakes relevant to a specific archetype.
        
        Args:
            archetype_name: One of ARCHETYPES
            
        Returns:
            Dict mapping mistake category → formatted text
        """
        srs = self._load_srs(archetype_name)
        mistakes = srs.get('critical_mistakes', [])
        
        # Format mistakes
        lines = ["# Critical Mistakes to Avoid"]
        for i, mistake in enumerate(mistakes, 1):
            lines.append("")
            lines.append(f"## {i}. {mistake.get('mistake', '')}")
            lines.append("")
            lines.append(f"**❌ Wrong:**")
            lines.append(f"```c")
            lines.append(mistake.get('wrong', ''))
            lines.append("```")
            lines.append("")
            lines.append(f"**✅ Right:**")
            lines.append(f"```c")
            lines.append(mistake.get('right', ''))
            lines.append("```")
            lines.append("")
            lines.append(f"**Why:** {mistake.get('why', '')}")
        
        return {'critical_mistakes': '\n'.join(lines)}
    
    def get_bundle(self, archetype_name: str) -> Dict[str, Any]:
        """Get complete knowledge bundle for an archetype.
        
        Includes archetype doc, skeleton, and relevant pitfalls.
        
        Args:
            archetype_name: One of ARCHETYPES
            
        Returns:
            Dict with keys: 'archetype', 'skeleton', 'pitfalls', 'srs'
        """
        return {
            'archetype': self.get_archetype(archetype_name),
            'skeleton': self.get_skeleton(archetype_name),
            'pitfalls': self.get_pitfalls(archetype_name),
            'srs': self.get_srs(archetype_name)  # New: full SRS JSON
        }
    
    def list_archetypes(self) -> List[str]:
        """List all available archetypes."""
        return self.ARCHETYPES.copy()


# Convenience functions for quick access

def get_archetype_bundle(archetype: str) -> Dict[str, any]:
    """Quick access: get full knowledge bundle for archetype."""
    retriever = KnowledgeRetriever()
    return retriever.get_bundle(archetype)


def get_skeleton_code(archetype: str) -> str:
    """Quick access: get just the skeleton code."""
    retriever = KnowledgeRetriever()
    return retriever.get_skeleton(archetype)


def get_srs(archetype: str) -> Dict[str, Any]:
    """Quick access: get full SRS JSON for archetype."""
    retriever = KnowledgeRetriever()
    return retriever.get_srs(archetype)


# Example usage
if __name__ == "__main__":
    retriever = KnowledgeRetriever()
    
    print("Available archetypes:")
    for arch in retriever.list_archetypes():
        print(f"  - {arch}")
    
    print("\n" + "="*60)
    print("Example: Object Lifecycle Bundle")
    print("="*60)
    
    bundle = retriever.get_bundle("object_lifecycle")
    
    print("\n[Archetype Doc Preview]")
    print(bundle['archetype'][:500] + "...\n")
    
    print("[Skeleton Code Preview]")
    print(bundle['skeleton'][:400] + "...\n")
    
    print(f"[Relevant Pitfalls: {list(bundle['pitfalls'].keys())}]")
    
    print("\n[SRS JSON Keys]")
    print(list(bundle['srs'].keys()))

