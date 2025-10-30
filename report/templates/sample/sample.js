"use strict";

document.addEventListener('DOMContentLoaded', function() {
    // Agent sections expand/collapse buttons
    const agentSectionsExpandAllButton = document.getElementById('agent-sections-expand-all');
    if (agentSectionsExpandAllButton) {
        agentSectionsExpandAllButton.addEventListener('click', () => {
            document.querySelectorAll('.agent-section').forEach(section => {
                const alpineData = Alpine.$data(section);
                if (alpineData) {
                    alpineData.open = true;
                }
            });
        });
    }

    const agentSectionsCollapseAllButton = document.getElementById('agent-sections-collapse-all');
    if (agentSectionsCollapseAllButton) {
        agentSectionsCollapseAllButton.addEventListener('click', () => {
            document.querySelectorAll('.agent-section').forEach(section => {
                const alpineData = Alpine.$data(section);
                if (alpineData) {
                    alpineData.open = false;
                }
            });
        });
    }
});

function copyGcsUrl(button) {
    const gcsUrlElement = document.getElementById('gcs-url-text');
    if (!gcsUrlElement) {
        console.error('GCS URL element not found');
        return;
    }

    const gcsUrl = gcsUrlElement.textContent;

    navigator.clipboard.writeText(gcsUrl).then(() => {
        if (!button) {
            return;
        }

        const svg = button.querySelector('svg');
        if (!svg) {
            return;
        }

        const pathElement = svg.querySelector('path');
        if (!pathElement) {
            return;
        }

        const originalPath = pathElement.getAttribute('d');

        pathElement.setAttribute('d', 'M5 13l4 4L19 7');
        setTimeout(() => {
            pathElement.setAttribute('d', originalPath);
        }, 2000);
    }).catch(err => {
        console.error('Failed to copy GCS URL:', err);
        alert('Failed to copy URL to clipboard');
    });
}

