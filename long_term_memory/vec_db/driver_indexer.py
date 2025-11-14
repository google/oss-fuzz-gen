#!/usr/bin/env python3
"""
Driver Code Indexer for Vector Database

This script indexes all fuzz driver code from extracted_fuzz_drivers folder,
extracts project and API type information, generates embeddings, and stores
them in a vector database (Chroma) for similarity search.
"""

import os
import re
import json
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from functools import lru_cache
from openai import OpenAI
import tqdm
import chromadb
from chromadb.config import Settings


class DriverCodeIndexer:
    """Indexes fuzz driver code for vector search."""
    
    # Supported file extensions
    CODE_EXTENSIONS = {'.c', '.cc', '.cpp', '.cxx', '.c++'}
    
    # API type patterns (based on archetypes)
    API_TYPE_PATTERNS = {
        'simple_function_call': [
            r'[a-zA-Z_][a-zA-Z0-9_]*\s*\([^)]*\)',  # Simple function calls
        ],
        'object_lifecycle': [
            r'(_init|_create|_new|_alloc|_setup|_open)\s*\(',
            r'(_destroy|_free|_delete|_cleanup|_close|_release|_deinit|_fini)\s*\(',
        ],
        'streaming_api': [
            r'while\s*\([^)]*\)\s*\{[^}]*\w+\s*\(',  # Loop with function calls
            r'(inflate|decompress|parse.*chunk|stream.*next)',
        ],
        'callback_api': [
            r'callback\s*[=\(]',
            r'function\s*pointer',
            r'\.cb\s*=',
        ],
        'file_path_api': [
            r'(fopen|open|read|write|stat|access)\s*\(',
            r'file.*path|path.*file',
        ],
        'multi_parameter_api': [
            r'\w+\s*\([^)]*,\s*[^)]*,\s*[^)]*,\s*[^)]*\)',  # Many parameters
        ],
        'exception_handling_api': [
            r'(try|catch|throw|exception)',
        ],
        'global_initialization': [
            r'LLVMFuzzerInitialize\s*\(',
            r'int\s+LLVMFuzzerInitialize',
        ],
        'round_trip': [
            r'(parse|decode|unpack|deserialize).*?(serialize|encode|pack)',
            r'(serialize|encode|pack).*?(parse|decode|unpack|deserialize)',
            r'memcmp\s*\([^,]+,\s*serialized',
            r'round.*trip|roundtrip',
        ],
        'stateful_fuzzing': [
            r'static\s+\w+\s*\*\s*\w+\s*=\s*(NULL|nullptr)',
            r'static\s+\w+\s+\w+\s*=\s*(NULL|nullptr)',
            r'if\s*\(\s*!\s*\w+\s*\)\s*\{[^}]*CREATE',
            r'CONTEXT_RESET|context.*reset|reset.*context',
        ],
    }
    
    def __init__(self, 
                 drivers_dir: str = "extracted_fuzz_drivers",
                 persist_directory: str = "./chroma_db",
                 collection_name: str = "driver_code",
                 embedding_model: str = "text-embedding-3-large",
                 openai_api_key: Optional[str] = None):
        """
        Initialize the indexer.
        
        Args:
            drivers_dir: Path to extracted_fuzz_drivers directory
            persist_directory: Directory to persist Chroma database
            collection_name: Name of the Chroma collection
            embedding_model: OpenAI embedding model to use
            openai_api_key: OpenAI API key (if None, uses env var)
        """
        self.drivers_dir = Path(drivers_dir)
        self.persist_directory = Path(persist_directory)
        self.collection_name = collection_name
        self.embedding_model = embedding_model
        
        # Initialize OpenAI client
        if openai_api_key:
            self.client = OpenAI(api_key=openai_api_key)
        else:
            self.client = OpenAI()
        
        # Initialize Chroma client
        self.client_db = chromadb.PersistentClient(
            path=str(self.persist_directory),
            settings=Settings(anonymized_telemetry=False)
        )
        
        # Get or create collection
        try:
            self.collection = self.client_db.get_collection(name=self.collection_name)
            print(f"Loaded existing collection '{self.collection_name}' with {self.collection.count()} entries")
        except Exception:
            self.collection = self.client_db.create_collection(
                name=self.collection_name,
                metadata={"description": "Fuzz driver code vector database"}
            )
            print(f"Created new collection '{self.collection_name}'")
    
    def _is_code_file(self, file_path: Path) -> bool:
        """Check if file is a code file."""
        return file_path.suffix in self.CODE_EXTENSIONS
    
    def _extract_project_name(self, file_path: Path) -> str:
        """Extract project name from file path."""
        # Path format: extracted_fuzz_drivers/project_name/file.c
        parts = file_path.parts
        if len(parts) >= 2:
            return parts[-2]  # Project name is parent directory
        return "unknown"
    
    def _extract_api_name(self, file_path: Path, code_content: str) -> str:
        """Extract API name from file path or code content."""
        # Try to extract from filename first
        filename = file_path.stem
        # Remove common prefixes/suffixes
        filename = re.sub(r'^(fuzz_|fuzzer_|test_)', '', filename, flags=re.IGNORECASE)
        filename = re.sub(r'(_fuzzer|_test|_driver)$', '', filename, flags=re.IGNORECASE)
        
        # If filename is too generic, try to find function names in code
        if filename in ['main', 'fuzz', 'test', 'driver']:
            # Look for function calls in LLVMFuzzerTestOneInput
            func_pattern = r'([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^)]*\)'
            matches = re.findall(func_pattern, code_content[:2000])  # First 2000 chars
            if matches:
                # Filter out common fuzzer functions
                exclude = {'LLVMFuzzerTestOneInput', 'malloc', 'free', 'memcpy', 'memset'}
                for match in matches:
                    if match not in exclude and len(match) > 3:
                        return match
        
        return filename or "unknown"
    
    def _infer_api_type(self, code_content: str) -> str:
        """
        Infer API type from code content using pattern matching.
        
        Returns:
            API type name (archetype) or 'unknown'
        """
        code_lower = code_content.lower()
        
        # Score each API type based on pattern matches
        scores = {}
        for api_type, patterns in self.API_TYPE_PATTERNS.items():
            score = 0
            for pattern in patterns:
                matches = len(re.findall(pattern, code_content, re.IGNORECASE | re.MULTILINE))
                score += matches
            scores[api_type] = score
        
        # Return the type with highest score, or 'unknown' if no matches
        if scores and max(scores.values()) > 0:
            return max(scores, key=scores.get)
        return 'unknown'
    
    def _get_embedding(self, text: str) -> List[float]:
        """Get embedding for text using OpenAI API."""
        try:
            response = self.client.embeddings.create(
                input=[text],
                model=self.embedding_model
            )
            return response.data[0].embedding
        except Exception as e:
            print(f"Error getting embedding: {e}")
            return None
    
    def _prepare_text_for_embedding(self, code_content: str, 
                                     project: str, api_name: str, 
                                     api_type: str) -> str:
        """
        Prepare text for embedding generation.
        Includes code content with metadata for better search.
        """
        # Create a searchable text representation
        text_parts = [
            f"Project: {project}",
            f"API: {api_name}",
            f"API Type: {api_type}",
            "",
            "Code:",
            code_content[:8000]  # Limit to 8000 chars for embedding
        ]
        return "\n".join(text_parts)
    
    def index_driver_file(self, file_path: Path, force_reindex: bool = False) -> Optional[Dict]:
        """
        Index a single driver file.
        
        Args:
            file_path: Path to the driver file
            force_reindex: If True, reindex even if already exists
        
        Returns:
            Dict with indexing information or None if failed
        """
        try:
            # Read file content
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                code_content = f.read()
            
            # Skip if too short or doesn't contain fuzzer entry point
            if len(code_content) < 100 or 'LLVMFuzzerTestOneInput' not in code_content:
                return None
            
            # Extract metadata
            project = self._extract_project_name(file_path)
            api_name = self._extract_api_name(file_path, code_content)
            api_type = self._infer_api_type(code_content)
            
            # Check if already indexed (unless force_reindex)
            file_path_str = str(file_path)
            if not force_reindex:
                existing = self.collection.get(
                    where={"file_path": file_path_str},
                    limit=1
                )
                if existing['ids']:
                    return {'file_path': file_path_str, 'status': 'already_indexed'}
            
            # Prepare text for embedding
            embedding_text = self._prepare_text_for_embedding(
                code_content, project, api_name, api_type
            )
            
            # Generate embedding
            embedding = self._get_embedding(embedding_text)
            if embedding is None:
                return None
            
            # Create unique ID from file path
            doc_id = file_path_str.replace('/', '_').replace('\\', '_')
            
            # If force_reindex and document exists, delete it first
            if force_reindex:
                try:
                    # Try to delete existing document with this ID
                    self.collection.delete(ids=[doc_id])
                except Exception:
                    pass  # Ignore if doesn't exist
            
            # Add to Chroma collection
            # Store code_content in metadata (Chroma supports large metadata, but we'll truncate if needed)
            # For very large code, we store a reference and can read from file later
            code_content_truncated = code_content[:50000]  # Limit metadata size
            
            self.collection.add(
                ids=[doc_id],
                embeddings=[embedding],
                documents=[embedding_text],  # Store embedding_text for search
                metadatas=[{
                    'file_path': file_path_str,
                    'project': project,
                    'api_name': api_name,
                    'api_type': api_type,
                    'code_content': code_content_truncated,  # Store truncated code
                    'code_length': len(code_content),  # Store full length
                }]
            )
            
            return {
                'file_path': file_path_str,
                'project': project,
                'api_name': api_name,
                'api_type': api_type,
                'status': 'indexed'
            }
        except Exception as e:
            print(f"Error indexing {file_path}: {e}")
            return None
    
    def index_all_drivers(self, force_reindex: bool = False):
        """
        Index all driver files in the drivers directory.
        
        Args:
            force_reindex: If True, reindex all files even if they exist
        """
        print(f"Scanning {self.drivers_dir} for driver files...")
        
        # Find all code files
        code_files = []
        for root, dirs, files in os.walk(self.drivers_dir):
            for file in files:
                file_path = Path(root) / file
                if self._is_code_file(file_path):
                    code_files.append(file_path)
        
        print(f"Found {len(code_files)} code files")
        
        # Get existing indexed files (if not force_reindex)
        existing_files = set()
        if not force_reindex:
            try:
                existing_results = self.collection.get(limit=10000)  # Get all
                existing_files = {meta.get('file_path', '') for meta in existing_results.get('metadatas', [])}
                print(f"Skipping {len(existing_files)} already indexed files")
            except Exception as e:
                print(f"Warning: Could not check existing files: {e}")
        
        # Index files
        new_count = 0
        skipped_count = 0
        for file_path in tqdm.tqdm(code_files, desc="Indexing drivers"):
            file_path_str = str(file_path)
            
            # Skip if already indexed (unless force_reindex)
            if not force_reindex and file_path_str in existing_files:
                skipped_count += 1
                continue
            
            entry = self.index_driver_file(file_path, force_reindex=force_reindex)
            if entry and entry.get('status') == 'indexed':
                new_count += 1
        
        total_count = self.collection.count()
        print(f"Indexed {new_count} new files. Skipped {skipped_count} files. Total: {total_count} entries")
    
    def search_similar(self, query: str, n: int = 5, 
                      project_filter: Optional[str] = None,
                      api_type_filter: Optional[str] = None,
                      threshold: float = 0.7) -> List[Dict]:
        """
        Search for similar driver code.
        
        Args:
            query: Search query text
            n: Number of results to return
            project_filter: Filter by project name (optional)
            api_type_filter: Filter by API type (optional)
            threshold: Minimum similarity threshold (0-1)
        
        Returns:
            List of similar driver entries with similarity scores
        """
        # Check if collection is empty
        if self.collection.count() == 0:
            raise ValueError("Collection is empty. Run index_all_drivers() first.")
        
        # Get query embedding
        query_embedding = self._get_embedding(query)
        if query_embedding is None:
            return []
        
        # Build where clause for metadata filtering
        where_clause = {}
        if project_filter:
            where_clause['project'] = project_filter
        if api_type_filter:
            where_clause['api_type'] = api_type_filter
        
        # Search in Chroma
        # Query more results than needed to filter by threshold
        query_n = min(n * 10, 100)  # Query up to 100 results
        
        try:
            results = self.collection.query(
                query_embeddings=[query_embedding],
                n_results=query_n,
                where=where_clause if where_clause else None
            )
        except Exception as e:
            print(f"Error querying Chroma: {e}")
            return []
        
        # Process results
        if not results['ids'] or not results['ids'][0]:
            return []
        
        formatted_results = []
        for i, doc_id in enumerate(results['ids'][0]):
            distance = results['distances'][0][i] if results.get('distances') else None
            # Chroma returns L2 distance, convert to similarity (1 - normalized distance)
            # For cosine similarity, distance is already 1 - similarity
            if distance is not None:
                # Chroma uses cosine distance, similarity = 1 - distance
                similarity = 1 - distance
            else:
                similarity = 1.0  # Fallback if distance not available
            
            # Filter by threshold
            if similarity < threshold:
                continue
            
            metadata = results['metadatas'][0][i] if results.get('metadatas') else {}
            document = results['documents'][0][i] if results.get('documents') else ""
            
            # Get code content from metadata (or read from file if truncated)
            code_content = metadata.get('code_content', '')
            file_path = metadata.get('file_path', '')
            
            # If code was truncated, try to read from file
            code_length = metadata.get('code_length', 0)
            if code_length > 50000 and file_path:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        code_content = f.read()
                except Exception:
                    pass  # Use truncated version if file read fails
            
            formatted_results.append({
                'similarity': float(similarity),
                'file_path': file_path,
                'project': metadata.get('project', ''),
                'api_name': metadata.get('api_name', ''),
                'api_type': metadata.get('api_type', ''),
                'code_content': code_content,
                'embedding_text': document,
            })
            
            if len(formatted_results) >= n:
                break
        
        return formatted_results


def main():
    """Main function for command-line usage."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Index fuzz driver code for vector search")
    parser.add_argument('--drivers-dir', default='extracted_fuzz_drivers',
                        help='Path to extracted_fuzz_drivers directory')
    parser.add_argument('--db-dir', default='./chroma_db',
                        help='Chroma database directory')
    parser.add_argument('--collection', default='driver_code',
                        help='Chroma collection name')
    parser.add_argument('--force', action='store_true',
                        help='Force reindex all files')
    parser.add_argument('--model', default='text-embedding-3-large',
                        help='OpenAI embedding model')
    
    args = parser.parse_args()
    
    indexer = DriverCodeIndexer(
        drivers_dir=args.drivers_dir,
        persist_directory=args.db_dir,
        collection_name=args.collection,
        embedding_model=args.model
    )
    
    indexer.index_all_drivers(force_reindex=args.force)
    print(f"Index saved to Chroma database at {args.db_dir}")


if __name__ == '__main__':
    main()

