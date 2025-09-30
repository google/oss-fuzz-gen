"""
Storage Adapter interfaces and implementations for the Historical Results
Module.

This module provides abstract interfaces and concrete implementations for
different storage backends used by the Historical Results Module. It abstracts
the details of storage, access, and authentication from the data manager.

The storage adapters are designed to:
1. Provide a consistent interface for different storage backends
2. Handle authentication and access control
3. Translate between storage-specific formats and application data models
4. Support various query patterns for historical data retrieval
5. Manage connections and connection pooling

For more details on how this fits into the overall architecture, see the
historical_results_uml.jpg diagram.
"""
import csv
import datetime
import io
import json
import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional

# Import consolidated errors
from ossfuzz_py.errors import QueryError, StorageAdapterError

# Configure module logger
logger = logging.getLogger('ossfuzz_sdk.storage_adapter')

class StorageAdapter(ABC):
  """
  Abstract Base Class for Storage Adapters.

  Defines the contract for classes that provide access to historical
  OSS-Fuzz data stored in different backends.
  """

  @abstractmethod
  def __init__(self, config: Dict[str, Any]):
    """
    Initializes the storage adapter with necessary configuration.

    Args:
        config: A dictionary containing configuration specific to this adapter
                (e.g., connection strings, API keys, bucket names).
    """
    self.base_directory = None

  @abstractmethod
  def connect(self) -> None:
    """
    Establishes a connection to the storage backend if necessary.
    May not be needed for all adapter types (e.g., local file adapter).

    Raises:
        StorageAdapterError: If connection fails.
    """

  @abstractmethod
  def disconnect(self) -> None:
    """
    Closes the connection to the storage backend if one was established.
    """

  @abstractmethod
  def fetch_coverage_history(
      self,
      project_name: str,
      start_date: Optional[str] = None,
      end_date: Optional[str] = None,
      filters: Optional[Dict[str, Any]] = None
  ) -> List[Any]:  # Should return List[CoverageHistory] when model is defined
    """
    Fetches historical coverage data for a specific project.

    Args:
        project_name: The name of the OSS-Fuzz project.
        start_date: Optional start date for the data range (ISO format).
        end_date: Optional end date for the data range (ISO format).
        filters: Optional dictionary of additional filters
        (e.g., by fuzzer, by file).

    Returns:
        A list of data points representing coverage history
        (e.g., CoverageHistory objects).

    Raises:
        QueryError: If fetching data fails.
        StorageAdapterError: If not connected or connection lost.
    """

  @abstractmethod
  def fetch_crash_data(
      self,
      project_name: str,
      start_date: Optional[str] = None,
      end_date: Optional[str] = None,
      filters: Optional[Dict[str, Any]] = None
  ) -> List[Any]:  # Should return List[CrashData] when model is defined
    """
    Fetches historical crash data for a specific project.

    Args:
        project_name: The name of the OSS-Fuzz project.
        start_date: Optional start date for the data range (ISO format).
        end_date: Optional end date for the data range (ISO format).
        filters: Optional dictionary of additional filters
        (e.g., by crash signature, severity).

    Returns:
        A list of data points representing crash data (e.g., CrashData objects)

    Raises:
        QueryError: If fetching data fails.
        StorageAdapterError: If not connected or connection lost.
    """

  # - fetch_project_list()
  # - fetch_build_information(...)
  # - fetch_report_details(...)
  # - persist_data(...) (if SDK needs to write/cache processed data back
  #   to a persistent store)
  # - batch_fetch_data(...)
  # - get_metadata(...)

  # Consider adding methods for transaction management if applicable
  #  to any backend types:
  # - begin_transaction()
  # - commit_transaction()
  # - rollback_transaction()

class FileStorageAdapter(StorageAdapter):
  """
  Storage adapter for accessing historical data stored
  in local files (JSON, CSV).

  Expects a base directory where project data is stored in subdirectories named
  after the project_name. Inside each project directory, expects files like
  'coverage_history.json' or 'crash_data.csv'.
  """

  def __init__(self, config: Dict[str, Any]):
    """
    Initializes the FileStorageAdapter.

    Args:
        config: Configuration dictionary.
                Expected keys:
                - 'base_directory': Path to the root directory containing
                the data files.
    """
    super().__init__(config)
    self.base_directory = Path(config.get('storage_path', './oss_fuzz_data'))
    if not self.base_directory.exists() or not self.base_directory.is_dir():
      # For now, log a warning. In a real scenario, might create it or raise
      # error.
      print(f"Warning: Base directory {self.base_directory}"
            f"does not exist or is not a directory.")
      # raise ConfigurationError(f"Base directory {self.base_directory} not
      # found or not a directory.")
    # File system access doesn't require explicit connect/disconnect
    self._connected = False
    self.logger = logger

  def connect(self) -> None:
    """Establishes connection (no-op for file system)."""
    # For file system, connection is implicit. We can check if base_directory
    # is valid.
    if not self.base_directory.is_dir():
      # Allow creation if configured, or raise error
      try:
        self.base_directory.mkdir(parents=True, exist_ok=True)
        print(f"Info: Created base directory {self.base_directory}")
      except OSError as e:
        raise StorageAdapterError(f"Failed to access or create base directory "
                                  f"{self.base_directory}: {e}")
    self._connected = True
    print("FileStorageAdapter: Connection established "
          "(directory access confirmed/created).")

  def disconnect(self) -> None:
    """Closes connection (no-op for file system)."""
    self._connected = False
    self.logger.info("FileStorageAdapter: Disconnected (no-op).")

  def _get_project_data_path(self,
                             project_name: str,
                             data_type: str,
                             file_format: str = 'json') -> Path:
    """
    Constructs the path to a project's data file.
    Example: base_directory/project_name/project_name_coverage_history.json
    """
    project_dir = self.base_directory / project_name
    if not project_dir.is_dir():
      raise QueryError(f"Data directory for project '{project_name}' "
                       f"not found at {project_dir}")

    filename = f"{project_name}_{data_type}.{file_format}"
    file_path = project_dir / filename

    if not file_path.is_file():
      # This specific QueryError helps distinguish from directory not found
      raise QueryError(f"Data file '{filename}' not found in project directory "
                       f"{project_dir} for format {file_format}")

    return file_path

  def fetch_coverage_history(
      self,
      project_name: str,
      start_date: Optional[str] = None,
      end_date: Optional[str] = None,
      filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    if not self._connected:
      self.connect()

    data: List[Dict[str, Any]] = []
    file_path_used: Optional[Path] = None

    try:
      try:
        file_path = self._get_project_data_path(project_name,
                                                "coverage_history", "json")
        file_path_used = file_path
        with open(file_path, 'r', encoding='utf-8') as f:
          loaded_data = json.load(f)
          if not isinstance(loaded_data, list):
            raise QueryError(f"Coverage data in {file_path} is not a list.")
          data = loaded_data
        self.logger.info("Loaded coverage history from JSON: %s", file_path)
      except QueryError as qe_json:
        self.logger.debug(
            "JSON coverage_history for %s not found "
            "or failed to load: %s. Attempting CSV.", project_name, qe_json)
        try:
          file_path_csv = self._get_project_data_path(project_name,
                                                      "coverage_history", "csv")
          file_path_used = file_path_csv
          with open(file_path_csv, 'r', newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
              data.append(dict(row))
          self.logger.info("Loaded coverage history from CSV: %s",
                           file_path_csv)
        except QueryError as qe_csv:
          self.logger.warning(
              "No coverage_history data file (JSON or CSV) found "
              "for project '%s'. "
              "Errors: JSON Attempt: %s, CSV Attempt: %s", project_name,
              qe_json, qe_csv)
          return []

      # Date and other filtering would be applied here.
      # Skipped in this smaller edit.
      # For now, just return the loaded data.
      # data = self._filter_by_date(data,
      # start_date, end_date, date_field='timestamp')
      # if filters: data = self._apply_other_filters(data, filters)

      self.logger.info(
          "Successfully fetched coverage history for %s. "
          "Count: %s from %s", project_name, len(data),
          file_path_used if file_path_used else 'N/A')
      return data
    except json.JSONDecodeError as e:
      self.logger.error(
          "Error decoding JSON coverage data for %s "
          "from %s: %s", project_name, file_path_used, e)
      raise QueryError(f"Error decoding JSON coverage data for {project_name} "
                       f"from {file_path_used}: {e}")
    except Exception as e:
      self.logger.error("Failed to fetch coverage history for %s: %s",
                        project_name,
                        e,
                        exc_info=True)
      raise QueryError(
          f"Failed to fetch coverage history for {project_name}: {e}")

  def fetch_crash_data(
      self,
      project_name: str,
      start_date: Optional[str] = None,
      end_date: Optional[str] = None,
      filters: Optional[Dict[str, Any]] = None
  ) -> List[Dict[str, Any]]:  # Return type changed to List[Dict[str,Any]]
    if not self._connected:
      self.connect()

    data: List[Dict[str, Any]] = []
    file_path_used: Optional[Path] = None

    try:
      try:
        file_path = self._get_project_data_path(project_name, "crash_data",
                                                "json")
        file_path_used = file_path
        with open(file_path, 'r', encoding='utf-8') as f:
          loaded_data = json.load(f)
          if not isinstance(loaded_data, list):
            raise QueryError(f"Crash data in {file_path} is not a list.")
          data = loaded_data
        self.logger.info("Loaded crash data from JSON: %s", file_path)
      except QueryError as qe_json:
        self.logger.debug(
            "JSON crash_data for %s not found or failed "
            "to load: %s. Attempting CSV.", project_name, qe_json)
        try:
          file_path_csv = self._get_project_data_path(project_name,
                                                      "crash_data", "csv")
          file_path_used = file_path_csv
          with open(file_path_csv, 'r', newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
              data.append(dict(row))
          self.logger.info("Loaded crash data from CSV: %s", file_path_csv)
        except QueryError as qe_csv:
          self.logger.warning(
              "No crash_data file (JSON or CSV) found "
              "for project '%s'. "
              "Errors: JSON Attempt: %s, CSV Attempt: %s", project_name,
              qe_json, qe_csv)
          return []

      self.logger.info(
          "Successfully fetched crash data for "
          "%s. Count: %s from %s", project_name, len(data),
          file_path_used if file_path_used else 'N/A')
      return data
    except json.JSONDecodeError as e:
      self.logger.error("Error decoding JSON crash data for "
                        "%s from %s: %s", project_name, file_path_used, e)
      raise QueryError(f"Error decoding JSON crash data for {project_name} "
                       f"from {file_path_used}: {e}")
    except Exception as e:
      self.logger.error("Failed to fetch crash data for %s: %s",
                        project_name,
                        e,
                        exc_info=True)
      raise QueryError(f"Failed to fetch crash data for {project_name}: {e}")

class GCSStorageAdapter(StorageAdapter):
  """
  Storage adapter for accessing historical data from Google Cloud Storage (GCS)
  Assumes data is stored in GCS buckets, potentially as JSON or CSV files.

  Expected config keys:
  - 'gcs_project_id': Your Google Cloud project ID
  (optional if client handles auth another way).
  - 'gcs_bucket_name': The name of the GCS bucket where data is stored.
  - 'gcs_credentials_path': Optional path to GCP service account JSON key file.
  - 'gcs_data_path_template': Template for object names,
      e.g., '{project_name}/{data_type}.{format}'
      (default: '{project_name}/{project_name}_{data_type}.{format}').
  """

  def __init__(self, config: Dict[str, Any]):
    super().__init__(config)
    self.bucket_name = config.get('gcs_bucket_name')
    if not self.bucket_name:
      raise StorageAdapterError(
          "GCSStorageAdapter: 'gcs_bucket_name' is required in config.")

    self.project_id = config.get(
        'gcs_project_id')  # Optional, client might infer
    self.credentials_path = config.get('gcs_credentials_path')
    self.path_template = config.get(
        'storage_path', '{project_name}/'
        '{project_name}_{data_type}.{format}')

    self._client: Optional[Any] = None  # google.cloud.storage.Client
    self._bucket: Optional[Any] = None  # google.cloud.storage.Bucket
    self._connected: bool = False
    self.logger = logger

    self.gcp_storage_client = None
    try:
      from google.cloud import storage
      self.gcp_storage_client = storage.Client
      self.logger.info("Google Cloud Storage components "
                       "loaded successfully for GCSStorageAdapter.")
    except ImportError:
      self.logger.warning(
          "Google Cloud Storage library not found. "
          "GCSStorageAdapter will not be fully functional. "
          "Please install it (e.g., pip install google-cloud-storage).")

  def connect(self) -> None:
    if self._connected and self._client and self._bucket:
      self.logger.info("GCSStorageAdapter: Already connected.")
      return

    if not self.gcp_storage_client:
      self.logger.error(
          "Google Cloud Storage library is not available. Cannot connect.")
      raise StorageAdapterError(
          "GCSStorageAdapter: google-cloud-storage library not found.")

    try:
      self.logger.info("GCSStorageAdapter: Connecting to GCS bucket '%s'.",
                       self.bucket_name)
      if self.credentials_path:
        self._client = self.gcp_storage_client.from_service_account_json(
            self.credentials_path, project=self.project_id)  # type: ignore
      elif self.project_id:
        self._client = self.gcp_storage_client(
            project=self.project_id)  # type: ignore
      else:
        self._client = self.gcp_storage_client()  # type: ignore

      self._bucket = self._client.bucket(self.bucket_name)  # type: ignore

      # Test connection by checking if the bucket exists / is accessible
      if not self._bucket.exists():  # type: ignore
        self.logger.error(
            "GCS bucket '%s' does not exist or is not accessible.",
            self.bucket_name)
        raise StorageAdapterError(
            f"GCSStorageAdapter: Bucket '{self.bucket_name}' not found or "
            "inaccessible.")

      self._connected = True
      self.logger.info(
          "GCSStorageAdapter: Successfully connected to GCS bucket '%s'.",
          self.bucket_name)
    except ImportError:
      self.logger.error(
          "google-cloud-storage library not installed. Cannot connect to GCS.")
      raise StorageAdapterError(
          "GCSStorageAdapter: google-cloud-storage library "
          "required but not installed.")
    except Exception as e:  # Catch generic GCS client errors
      self.logger.error("GCSStorageAdapter: Failed to connect to GCS: %s",
                        e,
                        exc_info=True)
      self._client = None
      self._bucket = None
      self._connected = False
      raise StorageAdapterError(
          f"GCSStorageAdapter: GCS connection failed: {e}")

  def disconnect(self) -> None:
    # GCS client typically doesn't require explicit close for simple operations,
    # but good practice to nullify if managing state.
    if self._client:
      # self._client.close() # For some clients or transports,
      # a close might be available.
      # For google-cloud-storage, client instances are generally lightweight.
      self.logger.info("GCSStorageAdapter: Client instance cleared "
                       "(disconnect is mostly a no-op).")
    self._client = None
    self._bucket = None
    self._connected = False
    self.logger.info("GCSStorageAdapter: Disconnected "
                     "(client and bucket references cleared).")

  # Duplicating _parse_date_string and _filter_by_date from FileStorageAdapter
  # for now to avoid complex inheritance decisions at this stage.
  # Consider refactoring to utils later.
  def _parse_date_string(
      self,
      date_str: str,
      record_identifier: str = "record") -> Optional[datetime.date]:
    """Attempts to parse a date string into a date object,
    trying multiple common formats."""
    formats_to_try = [
        "%Y-%m-%d", "%Y/%m/%d", "%m/%d/%Y", "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%SZ"
    ]
    for fmt in formats_to_try:
      try:
        return datetime.datetime.strptime(date_str, fmt).date()
      except ValueError:
        continue
      except TypeError:
        self.logger.warning("Date string None/not string for %s",
                            record_identifier)
        return None
    self.logger.warning("Could not parse date string '%s' for %s.", date_str,
                        record_identifier)
    return None

  def _filter_by_date(self,
                      data: List[Dict[str, Any]],
                      start_date_str: Optional[str],
                      end_date_str: Optional[str],
                      date_key: str = "date") -> List[Dict[str, Any]]:
    """Filters a list of records by date, returning a new list."""
    if not start_date_str and not end_date_str:
      return data
    parsed_start_date = self._parse_date_string(start_date_str, "start_date") \
      if start_date_str else None
    parsed_end_date = self._parse_date_string(end_date_str, "end_date") \
      if end_date_str else None
    if start_date_str and not parsed_start_date:
      self.logger.warning("Bad start_date '%s'", start_date_str)
    if end_date_str and not parsed_end_date:
      self.logger.warning("Bad end_date '%s'", end_date_str)
    if not parsed_start_date and not parsed_end_date:
      return data

    filtered = []
    for idx, record in enumerate(data):
      val = record.get(date_key)
      if not val or not isinstance(val, str):
        continue
      rec_date = self._parse_date_string(val,
                                         f"record {idx + 1} (key: {date_key})")
      if not rec_date:
        continue
      if parsed_start_date and rec_date < parsed_start_date:
        continue
      if parsed_end_date and rec_date > parsed_end_date:
        continue
      filtered.append(record)
    self.logger.info("Date filtering reduced %s to %s records.", len(data),
                     len(filtered))
    return filtered

  def _get_object_path(self, project_name: str, data_type: str,
                       file_format: str) -> str:
    """Constructs the GCS object path using the configured template."""
    return self.path_template.format(project_name=project_name,
                                     data_type=data_type,
                                     format=file_format)

  # pylint: disable=inconsistent-return-statements
  def _fetch_data_from_gcs(self, object_path: str,
                           file_format: str) -> List[Dict[str, Any]]:
    """Helper to fetch and parse data (JSON/CSV) from a GCS object."""
    if not self._connected or not self._bucket or not self._client:
      self.logger.error("GCSStorageAdapter: Not connected. Cannot fetch data.")
      raise StorageAdapterError("GCSStorageAdapter: Not connected.")

    self.logger.info(
        "GCSStorageAdapter: Attempting to fetch data from "
        "gcs://%s/%s", self.bucket_name, object_path)
    blob = self._bucket.blob(object_path)  # type: ignore

    if not blob.exists():  # type: ignore
      self.logger.warning("GCS object gs://%s/%s not found.", self.bucket_name,
                          object_path)
      raise QueryError(f"GCS object not found: {object_path}")

    try:
      data_str = blob.download_as_text()  # type: ignore
      if file_format == "json":
        loaded_data = json.loads(data_str)
        if not isinstance(loaded_data, list):
          raise QueryError(
              f"Data in GCS object {object_path} is not a list (JSON).")
        return loaded_data
      if file_format == "csv":
        # Use io.StringIO to treat the string as a file for csv.DictReader
        csvfile = io.StringIO(data_str)
        reader = csv.DictReader(csvfile)
        return [dict(row) for row in reader]
      # Should not happen if called correctly
      raise QueryError(
          f"Unsupported file format '{file_format}' for GCS fetch.")
    except json.JSONDecodeError as e:
      self.logger.error("Error decoding JSON from GCS object %s: %s",
                        object_path, e)
      raise QueryError(f"Invalid JSON data in GCS object {object_path}: {e}")
    except Exception as e:
      self.logger.error("Error downloading or parsing GCS object %s: %s",
                        object_path,
                        e,
                        exc_info=True)
      raise QueryError(f"Failed to process GCS object {object_path}: {e}")

  def fetch_coverage_history(
      self,
      project_name: str,
      start_date: Optional[str] = None,
      end_date: Optional[str] = None,
      filters: Optional[Dict[str, Any]] = None) -> List[Any]:
    if not self._connected:
      self.connect()
    self.logger.info("Fetching coverage history for '%s' from GCS.",
                     project_name)
    data: List[Dict[str, Any]] = []
    object_path_used: str = ""

    try:
      try:
        object_path_json = self._get_object_path(project_name,
                                                 "coverage_history", "json")
        object_path_used = object_path_json
        data = self._fetch_data_from_gcs(object_path_json, "json")
        self.logger.info("Loaded coverage history from GCS (JSON): gcs://%s/%s",
                         self.bucket_name, object_path_json)
      except QueryError as qe_json:
        # Catch if JSON object not found or bad format
        self.logger.debug(
            "GCS JSON coverage_history for %s not found/failed: %s. "
            "Trying CSV.", project_name, qe_json)
        try:
          object_path_csv = self._get_object_path(project_name,
                                                  "coverage_history", "csv")
          object_path_used = object_path_csv
          data = self._fetch_data_from_gcs(object_path_csv, "csv")
          self.logger.info(
              "Loaded coverage history from GCS (CSV): gcs://%s/%s",
              self.bucket_name, object_path_csv)
        except QueryError as qe_csv:
          self.logger.warning(
              "No coverage_history GCS object (JSON/CSV) for %s. "
              "Errors: JSON: %s, CSV: %s", project_name, qe_json, qe_csv)
          return []

      if data and (start_date or end_date):
        date_key = filters.get("date_field_name", "date") if filters else "date"
        # Simplified key check for brevity for now
        data = self._filter_by_date(data,
                                    start_date,
                                    end_date,
                                    date_key=date_key)

      return data
    except Exception as e:
      self.logger.error(
          "GCSStorageAdapter: Error fetching coverage for %s from %s: %s",
          project_name,
          object_path_used,
          e,
          exc_info=True)
      raise QueryError(
          f"GCSStorageAdapter: Failed to fetch coverage for {project_name}: {e}"
      )

  def fetch_crash_data(self,
                       project_name: str,
                       start_date: Optional[str] = None,
                       end_date: Optional[str] = None,
                       filters: Optional[Dict[str, Any]] = None) -> List[Any]:
    if not self._connected:
      self.connect()
    self.logger.info("Fetching crash data for '%s' from GCS.", project_name)
    data: List[Dict[str, Any]] = []
    object_path_used: str = ""

    try:
      try:
        object_path_json = self._get_object_path(project_name, "crash_data",
                                                 "json")
        object_path_used = object_path_json
        data = self._fetch_data_from_gcs(object_path_json, "json")
        self.logger.info("Loaded crash data from GCS (JSON): gcs://%s/%s",
                         self.bucket_name, object_path_json)
      except QueryError as qe_json:
        self.logger.debug(
            "GCS JSON crash_data for %s not found/failed: %s. Trying CSV.",
            project_name, qe_json)
        try:
          object_path_csv = self._get_object_path(project_name, "crash_data",
                                                  "csv")
          object_path_used = object_path_csv
          data = self._fetch_data_from_gcs(object_path_csv, "csv")
          self.logger.info("Loaded crash data from GCS (CSV): gcs://%s/%s",
                           self.bucket_name, object_path_csv)
        except QueryError as qe_csv:
          self.logger.warning(
              "No crash_data GCS object (JSON/CSV) for %s. "
              "Errors: JSON: %s, CSV: %s", project_name, qe_json, qe_csv)
          return []

      if data and (start_date or end_date):
        date_key = filters.get("date_field_name", "date") if filters else "date"
        # Simplified key check for brevity for now
        data = self._filter_by_date(data,
                                    start_date,
                                    end_date,
                                    date_key=date_key)

      return data
    except Exception as e:
      self.logger.error(
          "GCSStorageAdapter: Error fetching crash data for %s from %s: %s",
          project_name,
          object_path_used,
          e,
          exc_info=True)
      raise QueryError(f"GCSStorageAdapter: Failed to fetch crash data for "
                       f"{project_name}: {e}")
