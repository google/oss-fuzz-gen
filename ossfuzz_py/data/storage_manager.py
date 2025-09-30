"""
Central Storage Manager for the OSS-Fuzz SDK.

This module provides the main StorageManager class that coordinates
storage operations across different backends and provides a unified interface
for storing and retrieving artifacts, results, and metadata.

The StorageManager acts as a facade that:
1. Manages different storage backends through adapters
2. Provides a consistent interface for storage operations
3. Handles backend selection and configuration
4. Manages access control and authentication
"""

import json
import logging
import pickle
from typing import Any, Dict, List, Optional

from ossfuzz_py.data.storage_adapter import (FileStorageAdapter,
                                             GCSStorageAdapter, StorageAdapter)
from ossfuzz_py.errors import ConfigurationError, StorageManagerError

# Configure module logger
logger = logging.getLogger('ossfuzz_sdk.storage_manager')

class StorageManager:
  """
  Central storage management class that coordinates storage operations
  across different backends and provides a unified interface.

  This class acts as the main entry point for all storage operations in the SDK,
  abstracting the complexity of different storage backends and providing
  a consistent API for storing and retrieving data.

  Example:
      ```python
      # Create a storage manager with local backend
      config = {
          'storage_backend': 'local',
          'storage_path': '/path/to/storage'
      }
      storage = StorageManager(config)

      # Store data
      storage.store('my-key', {'data': 'value'})

      # Retrieve data
      data = storage.retrieve('my-key')

      # List keys
      keys = storage.list('prefix/')

      # Delete data
      storage.delete('my-key')
      ```
  """

  def __init__(self, config: Dict[str, Any]):
    """
    Initialize the StorageManager.

    Args:
        config: Configuration dictionary containing:
            - storage_backend: Backend type ('local', 'gcs', 's3', 'database')
            - Backend-specific configuration options

    Raises:
        ConfigurationError: If configuration is invalid
        StorageManagerError: If initialization fails
    """
    self.config = config
    self.logger = logger

    # Get backend type
    self.backend = config.get('storage_backend', 'local')

    # Initialize the appropriate adapter
    self.adapter = self._get_adapter()

    # Connect to storage if needed
    try:
      self.adapter.connect()
      self.logger.info("StorageManager initialized with %s backend",
                       self.backend)
    except Exception as e:
      raise StorageManagerError(
          f"Failed to initialize storage backend: {str(e)}")

  def _get_adapter(self) -> StorageAdapter:
    """
    Get the appropriate storage adapter based on configuration.

    Returns:
        StorageAdapter: Configured storage adapter

    Raises:
        ConfigurationError: If backend type is unsupported
    """
    if self.backend == 'local':
      return FileStorageAdapter(self.config)
    if self.backend == 'gcs':
      return GCSStorageAdapter(self.config)
    raise ConfigurationError(f"Unsupported storage backend: {self.backend}")

  def store(self, key: str, data: Any) -> str:  # pylint: disable=inconsistent-return-statements
    """
    Store data with the given key.

    Args:
        key: Storage key/path for the data
        data: Data to store (can be dict, list, str, bytes,
        or any serializable object)

    Returns:
        str: Storage path or identifier where data was stored

    Raises:
        StorageManagerError: If storage operation fails
    """
    try:
      self.logger.debug("Storing data with key: %s", key)

      # For file-based storage, implement generic storage
      if isinstance(self.adapter, FileStorageAdapter):
        return self._store_file_data(key, data)

      # For other adapters, raise not implemented
      raise StorageManagerError(
          f"Generic store operation not implemented for {self.backend} backend")

    except Exception as e:
      self.logger.error("Failed to store data with key %s: %s", key, str(e))
      raise StorageManagerError(f"Failed to store data: {str(e)}")

  def _store_file_data(self, key: str, data: Any) -> str:
    """Store data using file-based storage."""
    if not isinstance(self.adapter, FileStorageAdapter):
      raise StorageManagerError("Expected FileStorageAdapter")
    base_dir = self.adapter.base_directory
    if base_dir is None:
      raise StorageManagerError("Base directory not configured")
    file_path = base_dir / key

    # Create parent directories
    file_path.parent.mkdir(parents=True, exist_ok=True)

    # Determine storage format based on data type
    if isinstance(data, (dict, list)):
      # Store as JSON
      with open(file_path.with_suffix('.json'), 'w') as f:
        json.dump(data, f, indent=2)
      return str(file_path.with_suffix('.json'))
    if isinstance(data, str):
      # Store as text
      with open(file_path.with_suffix('.txt'), 'w') as f:
        f.write(data)
      return str(file_path.with_suffix('.txt'))
    if isinstance(data, bytes):
      # Store as binary
      with open(file_path, 'wb') as f:
        f.write(data)
      return str(file_path)
    # Store as pickle
    with open(file_path.with_suffix('.pkl'), 'wb') as f:
      pickle.dump(data, f)
    return str(file_path.with_suffix('.pkl'))

  def retrieve(self, key: str) -> Any:  # pylint: disable=inconsistent-return-statements
    """
    Retrieve data with the given key.

    Args:
        key: Storage key/path for the data

    Returns:
        Any: Retrieved data

    Raises:
        StorageManagerError: If retrieval fails
        KeyError: If key is not found
    """
    try:
      self.logger.debug("Retrieving data with key: %s", key)

      # For file-based storage, implement generic retrieval
      if isinstance(self.adapter, FileStorageAdapter):
        return self._retrieve_file_data(key)

      # For other adapters, raise not implemented
      raise StorageManagerError(
          f"Generic retrieve operation not implemented for {self.backend} "
          "backend")

    except KeyError:
      raise
    except Exception as e:
      self.logger.error("Failed to retrieve data with key %s: %s", key, str(e))
      raise StorageManagerError(f"Failed to retrieve data: {str(e)}")

  def _retrieve_file_data(self, key: str) -> Any:
    """Retrieve data using file-based storage."""
    if not isinstance(self.adapter, FileStorageAdapter):
      raise StorageManagerError("Expected FileStorageAdapter")
    base_dir = self.adapter.base_directory
    if base_dir is None:
      raise StorageManagerError("Base directory not configured")
    base_path = base_dir / key

    # Try different file extensions
    for ext in ['.json', '.txt', '.pkl', '']:
      file_path = base_path.with_suffix(ext) if ext else base_path
      if file_path.exists():
        if ext == '.json':
          with open(file_path, 'r') as f:
            return json.load(f)
        elif ext == '.txt':
          with open(file_path, 'r') as f:
            return f.read()
        elif ext == '.pkl':
          with open(file_path, 'rb') as f:
            return pickle.load(f)
        else:
          # Binary file
          with open(file_path, 'rb') as f:
            return f.read()

    raise KeyError(f"Key not found: {key}")

  def list(self, prefix: Optional[str] = None) -> List[str]:  # pylint: disable=inconsistent-return-statements
    """
    List keys with the given prefix.

    Args:
        prefix: Optional prefix to filter keys

    Returns:
        List[str]: List of matching keys

    Raises:
        StorageManagerError: If listing fails
    """
    try:
      self.logger.debug("Listing keys with prefix: %s", prefix)

      # For file-based storage, implement generic listing
      if isinstance(self.adapter, FileStorageAdapter):
        return self._list_file_keys(prefix)

      # For other adapters, raise not implemented
      raise StorageManagerError(
          f"Generic list operation not implemented for {self.backend} backend")

    except Exception as e:
      self.logger.error("Failed to list keys with prefix %s: %s", prefix,
                        str(e))
      raise StorageManagerError(f"Failed to list keys: {str(e)}")

  def _list_file_keys(self, prefix: Optional[str] = None) -> List[str]:
    """List keys using file-based storage."""
    if not isinstance(self.adapter, FileStorageAdapter):
      raise StorageManagerError("Expected FileStorageAdapter")
    base_dir = self.adapter.base_directory
    if base_dir is None:
      raise StorageManagerError("Base directory not configured")

    if prefix:
      search_path = base_dir / prefix
    else:
      search_path = base_dir

    keys = []
    if search_path.exists():
      for file_path in search_path.rglob('*'):
        if file_path.is_file():
          # Get relative path from base directory
          rel_path = file_path.relative_to(base_dir)
          # Remove file extension for cleaner keys
          key = str(rel_path.with_suffix(''))
          keys.append(key)

    return sorted(keys)

  def delete(self, key: str) -> bool:  # pylint: disable=inconsistent-return-statements
    """
    Delete data with the given key.

    Args:
        key: Storage key/path for the data

    Returns:
        bool: True if deletion was successful, False otherwise

    Raises:
        StorageManagerError: If deletion fails
    """
    try:
      self.logger.debug("Deleting data with key: %s", key)

      # For file-based storage, implement generic deletion
      if isinstance(self.adapter, FileStorageAdapter):
        return self._delete_file_data(key)

      # For other adapters, raise not implemented
      raise StorageManagerError(
          f"Generic delete operation not implemented for {self.backend} backend"
      )

    except Exception as e:
      self.logger.error("Failed to delete data with key %s: %s", key, str(e))
      raise StorageManagerError(f"Failed to delete data: {str(e)}")

  def _delete_file_data(self, key: str) -> bool:
    """Delete data using file-based storage."""
    if not isinstance(self.adapter, FileStorageAdapter):
      raise StorageManagerError("Expected FileStorageAdapter")
    base_dir = self.adapter.base_directory
    if base_dir is None:
      raise StorageManagerError("Base directory not configured")
    base_path = base_dir / key

    # Try different file extensions
    deleted = False
    for ext in ['.json', '.txt', '.pkl', '']:
      file_path = base_path.with_suffix(ext) if ext else base_path
      if file_path.exists():
        file_path.unlink()
        deleted = True

    return deleted

  def disconnect(self) -> None:
    """
    Disconnect from the storage backend.
    """
    try:
      self.adapter.disconnect()
      self.logger.info("StorageManager disconnected")
    except Exception as e:
      self.logger.warning("Error during disconnect: %s", str(e))

  def __enter__(self):
    """Context manager entry."""
    return self

  def __exit__(self, exc_type, exc_val, exc_tb):
    """Context manager exit."""
    self.disconnect()
