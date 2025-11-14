// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

const GCS_URL_ELEMENT_ID = 'gcs-url-text';
const AGENT_SECTION_SELECTOR = '.agent-section';
const EXPAND_ALL_BUTTON_ID = 'agent-sections-expand-all';
const COLLAPSE_ALL_BUTTON_ID = 'agent-sections-collapse-all';

/**
 * Toggles the open state of all agent sections in the document.
 * @param {boolean} open - Whether to open (true) or close (false) the sections.
 */
function toggleAgentSections(open) {
    document.querySelectorAll(AGENT_SECTION_SELECTOR).forEach(section => {
        const alpineData = Alpine.$data(section);
        if (alpineData) {
            alpineData.open = open;
        }
    });
}

/**
 * Copies the GCS URL to clipboard and displays a visual confirmation.
 * @param {HTMLElement} button - The button element that triggered the copy action.
 */
function copyGcsUrl(button) {
    const gcsUrlElement = document.getElementById(GCS_URL_ELEMENT_ID);
    if (!gcsUrlElement) {
        console.error('GCS URL element not found');
        return;
    }

    const gcsUrl = gcsUrlElement.textContent;

    navigator.clipboard.writeText(gcsUrl).then(() => {
        if (!button) {
            return;
        }

        const pathElement = button.querySelector('svg path');
        if (!pathElement) {
            return;
        }

        const originalPath = pathElement.getAttribute('d');

        // Checkmark icon SVG
        pathElement.setAttribute('d', 'M5 13l4 4L19 7');
        setTimeout(() => {
            pathElement.setAttribute('d', originalPath);
        }, 2000);
    }).catch(err => {
        console.error('Failed to copy GCS URL:', err);
        alert('Failed to copy URL to clipboard');
    });
}

document.addEventListener('DOMContentLoaded', function() {
    if (typeof hljs !== 'undefined') {
        hljs.highlightAll();
    }

    const agentSectionsExpandAllButton = document.getElementById(EXPAND_ALL_BUTTON_ID);
    if (agentSectionsExpandAllButton) {
        agentSectionsExpandAllButton.addEventListener('click', () => toggleAgentSections(true));
    }

    const agentSectionsCollapseAllButton = document.getElementById(COLLAPSE_ALL_BUTTON_ID);
    if (agentSectionsCollapseAllButton) {
        agentSectionsCollapseAllButton.addEventListener('click', () => toggleAgentSections(false));
    }
});
