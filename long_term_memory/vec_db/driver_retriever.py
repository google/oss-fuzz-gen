#!/usr/bin/env python3
"""
Driver Code Retriever for Similarity Search

Provides a high-level interface for retrieving similar fuzz driver code
from the indexed vector database.
"""

from pathlib import Path
from typing import List, Dict, Optional
from driver_indexer import DriverCodeIndexer
import chromadb


class DriverCodeRetriever:
    """High-level interface for retrieving similar driver code."""
    
    def __init__(self, 
                 persist_directory: str = "./chroma_db",
                 collection_name: str = "driver_code",
                 embedding_model: str = "text-embedding-3-large",
                 openai_api_key: Optional[str] = None):
        """
        Initialize the retriever.
        
        Args:
            persist_directory: Chroma database directory
            collection_name: Chroma collection name
            embedding_model: OpenAI embedding model to use
            openai_api_key: OpenAI API key (if None, uses env var)
        """
        self.indexer = DriverCodeIndexer(
            persist_directory=persist_directory,
            collection_name=collection_name,
            embedding_model=embedding_model,
            openai_api_key=openai_api_key
        )
        self.persist_directory = Path(persist_directory)
        self.collection_name = collection_name
    
    def search_by_description(self, 
                              description: str,
                              n: int = 5,
                              project: Optional[str] = None,
                              api_type: Optional[str] = None,
                              threshold: float = 0.7) -> List[Dict]:
        """
        Search for similar driver code by natural language description.
        
        Args:
            description: Natural language description of what you're looking for
                        (e.g., "fuzzer for JSON parsing", "streaming API with loops")
            n: Number of results to return
            project: Filter by project name (optional)
            api_type: Filter by API type/archetype (optional)
            threshold: Minimum similarity threshold (0-1)
        
        Returns:
            List of similar driver entries with similarity scores
        
        Example:
            >>> retriever = DriverCodeRetriever()
            >>> results = retriever.search_by_description(
            ...     "JSON parsing with error handling",
            ...     project="cjson",
            ...     n=3
            ... )
        """
        return self.indexer.search_similar(
            query=description,
            n=n,
            project_filter=project,
            api_type_filter=api_type,
            threshold=threshold
        )
    
    def search_by_code_snippet(self,
                               code_snippet: str,
                               n: int = 5,
                               project: Optional[str] = None,
                               api_type: Optional[str] = None,
                               threshold: float = 0.7) -> List[Dict]:
        """
        Search for similar driver code by code snippet.
        
        Args:
            code_snippet: Code snippet to search for
            n: Number of results to return
            project: Filter by project name (optional)
            api_type: Filter by API type/archetype (optional)
            threshold: Minimum similarity threshold (0-1)
        
        Returns:
            List of similar driver entries with similarity scores
        
        Example:
            >>> retriever = DriverCodeRetriever()
            >>> results = retriever.search_by_code_snippet(
            ...     "while (stream_next()) { process(); }",
            ...     api_type="streaming_api"
            ... )
        """
        return self.indexer.search_similar(
            query=code_snippet,
            n=n,
            project_filter=project,
            api_type_filter=api_type,
            threshold=threshold
        )
    
    def search_by_api_name(self,
                          api_name: str,
                          project: Optional[str] = None,
                          n: int = 5,
                          threshold: float = 0.7) -> List[Dict]:
        """
        Search for driver code by API function name.
        
        Args:
            api_name: Name of the API function (e.g., "curl_easy_perform")
            project: Filter by project name (optional)
            n: Number of results to return
            threshold: Minimum similarity threshold (0-1)
        
        Returns:
            List of similar driver entries with similarity scores
        """
        query = f"API function: {api_name}"
        return self.indexer.search_similar(
            query=query,
            n=n,
            project_filter=project,
            api_type_filter=None,
            threshold=threshold
        )
    
    def get_examples_by_type(self,
                            api_type: str,
                            project: Optional[str] = None,
                            n: int = 10) -> List[Dict]:
        """
        Get example driver code for a specific API type/archetype.
        
        Args:
            api_type: API type/archetype (e.g., "streaming_api", "object_lifecycle")
            project: Filter by project name (optional)
            n: Number of examples to return
        
        Returns:
            List of driver entries for the specified API type
        """
        # Use a generic query for the API type
        query = f"API type: {api_type}"
        return self.indexer.search_similar(
            query=query,
            n=n,
            project_filter=project,
            api_type_filter=api_type,
            threshold=0.5  # Lower threshold for type-based search
        )
    
    def get_examples_by_project(self,
                               project: str,
                               api_type: Optional[str] = None,
                               n: int = 10) -> List[Dict]:
        """
        Get example driver code for a specific project.
        
        Args:
            project: Project name (e.g., "curl", "cjson")
            api_type: Filter by API type (optional)
            n: Number of examples to return
        
        Returns:
            List of driver entries for the specified project
        """
        query = f"Project: {project}"
        return self.indexer.search_similar(
            query=query,
            n=n,
            project_filter=project,
            api_type_filter=api_type,
            threshold=0.5  # Lower threshold for project-based search
        )
    
    def list_projects(self) -> List[str]:
        """List all available projects in the index."""
        try:
            collection = self.indexer.collection
            if collection.count() == 0:
                return []
            
            # Get all metadata
            results = collection.get(limit=10000)
            projects = set()
            for metadata in results.get('metadatas', []):
                if 'project' in metadata:
                    projects.add(metadata['project'])
            return sorted(list(projects))
        except Exception:
            return []
    
    def list_api_types(self) -> List[str]:
        """List all available API types in the index."""
        try:
            collection = self.indexer.collection
            if collection.count() == 0:
                return []
            
            # Get all metadata
            results = collection.get(limit=10000)
            api_types = set()
            for metadata in results.get('metadatas', []):
                if 'api_type' in metadata:
                    api_types.add(metadata['api_type'])
            return sorted(list(api_types))
        except Exception:
            return []
    
    def get_statistics(self) -> Dict:
        """Get statistics about the indexed driver code."""
        try:
            collection = self.indexer.collection
            total_count = collection.count()
            
            if total_count == 0:
                return {
                    'total_drivers': 0,
                    'projects': [],
                    'api_types': []
                }
            
            # Get all metadata
            results = collection.get(limit=10000)
            projects = []
            api_types = []
            api_type_counts = {}
            project_counts = {}
            
            for metadata in results.get('metadatas', []):
                if 'project' in metadata:
                    project = metadata['project']
                    projects.append(project)
                    project_counts[project] = project_counts.get(project, 0) + 1
                
                if 'api_type' in metadata:
                    api_type = metadata['api_type']
                    api_types.append(api_type)
                    api_type_counts[api_type] = api_type_counts.get(api_type, 0) + 1
            
            return {
                'total_drivers': total_count,
                'num_projects': len(set(projects)),
                'num_api_types': len(set(api_types)),
                'projects': sorted(set(projects)),
                'api_types': sorted(set(api_types)),
                'api_type_distribution': api_type_counts,
                'project_distribution': project_counts
            }
        except Exception as e:
            print(f"Error getting statistics: {e}")
            return {
                'total_drivers': 0,
                'projects': [],
                'api_types': []
            }


# Convenience functions
def search_drivers(description: str, **kwargs) -> List[Dict]:
    """Quick search function."""
    retriever = DriverCodeRetriever()
    return retriever.search_by_description(description, **kwargs)


def get_examples(api_type: str, **kwargs) -> List[Dict]:
    """Quick function to get examples by API type."""
    retriever = DriverCodeRetriever()
    return retriever.get_examples_by_type(api_type, **kwargs)


if __name__ == '__main__':
    """Example usage."""
    retriever = DriverCodeRetriever()
    
    # Print statistics
    stats = retriever.get_statistics()
    print("Index Statistics:")
    print(f"  Total drivers: {stats['total_drivers']}")
    print(f"  Projects: {stats['num_projects']}")
    print(f"  API types: {stats['num_api_types']}")
    print(f"\nAPI Type Distribution:")
    for api_type, count in stats['api_type_distribution'].items():
        print(f"  {api_type}: {count}")
    
    # Example search
    print("\n" + "="*60)
    print("Example: Search for streaming API examples")
    print("="*60)
    results = retriever.search_by_description(
        "streaming API with loop and iteration limit",
        api_type="streaming_api",
        n=3
    )
    
    for i, result in enumerate(results, 1):
        print(f"\n[{i}] Similarity: {result['similarity']:.3f}")
        print(f"    Project: {result['project']}")
        print(f"    API: {result['api_name']}")
        print(f"    Type: {result['api_type']}")
        print(f"    File: {result['file_path']}")

