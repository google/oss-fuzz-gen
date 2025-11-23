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
import time
from datetime import datetime
from typing import Dict, List, Optional

from google.cloud import storage
from google.api_core.retry import Retry
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
            "targets": [self._format_target(t, project) for t in targets]
        }

    def _format_target(self, target: str, project: str) -> Dict:
        """Format target metadata with validation."""
        funcs = get_project_funcs(project).get(target, [])
        if not funcs:
            return {"path": target, "signatures": [], "language": "unknown"}
            
        return {
            "path": target,
            "signatures": [
                f['function_signature'] for f in funcs
                if 'LLVMFuzzerTestOneInput' not in f.get('function_name', '')
            ],
            "language": funcs[0].get('language', 'unknown')
        }

    @Retry()
    def _upload_project_data(self, project: str, bucket, data: Dict):
        """Upload JSON metadata to GCS with retries."""
        blob = bucket.blob(f"projects/{project}/metadata.json")
        blob.upload_from_string(
            json.dumps(data, indent=2),
            content_type="application/json"
        )

if __name__ == "__main__":
    GCSSynchronizer().sync_all()