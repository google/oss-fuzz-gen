# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Synchronizes OSS-Fuzz targets and benchmarks to GCS."""
import json
import logging
import os
from datetime import datetime
from typing import Dict, List, Optional

from google.cloud import storage
from data_prep.introspector import get_project_funcs, set_introspector_endpoints
from data_prep.target_collector import _get_targets
from experiment import oss_fuzz_checkout

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class GCSSynchronizer:
    """Handles metadata synchronization with GCS bucket."""
    
    def __init__(self):
        set_introspector_endpoints(os.getenv("INTROSPECTOR_ENDPOINT"))
        self.projects = self._get_oss_projects()
        self.bucket_name = os.getenv("GCS_BUCKET", "oss-fuzz-gen-targets")
        self.storage_client = storage.Client()
    
    def _get_oss_projects(self) -> List[str]:
        """Get OSS-Fuzz projects with optional limit."""
        projects = oss_fuzz_checkout.get_all_projects()
        return projects[:int(os.getenv("PROJECTS_LIMIT", 0))] if os.getenv("PROJECTS_LIMIT") else projects
    
    def sync_all(self):
        """Main synchronization workflow."""
        bucket = self.storage_client.bucket(self.bucket_name)
        for project in self.projects:
            try:
                if data := self._process_project(project):
                    self._upload_project_data(project, bucket, data)
            except Exception as e:
                logger.error(f"Failed {project}: {str(e)}")

    def _process_project(self, project: str) -> Optional[Dict]:
        """Process individual project data."""
        targets = _get_targets(project)
        if not targets:
            return None

        return {
            "project": project,
            "timestamp": datetime.utcnow().isoformat(),
            "targets": [{
                "path": target,
                "signatures": self._get_function_signatures(project, target),
                "language": self._detect_language(project, target)
            } for target in targets]
        }

    def _get_function_signatures(self, project: str, target: str) -> List[str]:
        """Extract function signatures from introspector."""
        funcs = get_project_funcs(project).get(target, [])
        return [
            f['function_signature'] for f in funcs
            if 'LLVMFuzzerTestOneInput' not in f.get('function_name', '')
        ]

    def _detect_language(self, project: str, target: str) -> str:
        """Detect implementation language."""
        funcs = get_project_funcs(project).get(target, [])
        return funcs[0]['language'] if funcs else "unknown"

    def _upload_project_data(self, project: str, bucket, data: Dict):
        """Upload JSON metadata to GCS."""
        blob = bucket.blob(f"projects/{project}/metadata.json")
        blob.upload_from_string(json.dumps(data, indent=2))

if __name__ == "__main__":
    GCSSynchronizer().sync_all()