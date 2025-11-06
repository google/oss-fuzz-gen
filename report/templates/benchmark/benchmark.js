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

const TAG_TYPES = ['system', 'instruction', 'task', 'solution'];
const TAG_REGEX = /<(system|instruction|task|solution)>([\s\S]*?)<\/\1>/g;
const STRUCTURED_PROMPT_SELECTOR = '#structured-prompt';
const ACCORDION_CONTENT_CLASS = 'accordion-content';
const ACCORDION_HEADER_CLASS = 'accordion-header';

const TAG_ICONS = {
    system: '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/></svg>',
    instruction: '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253"/></svg>',
    code: '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"/></svg>',
    task: '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"/></svg>',
    solution: '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>'
};

/**
 * Parses prompt tags from raw prompt text.
 * @param {string} rawPrompt - The raw prompt text containing XML-style tags.
 * @returns {Array<{type: string, content: string}>} Array of parsed tag objects.
 */
function parsePromptTags(rawPrompt) {
    const tags = [];
    let match;

    while ((match = TAG_REGEX.exec(rawPrompt)) !== null) {
        const [_, tagName, content] = match;
        const processedContent = tagName === 'solution' ? content : content.trim();
        tags.push({
            type: tagName,
            content: processedContent
        });
    }

    return tags;
}

/**
 * Creates an accordion section HTML for a prompt tag.
 * @param {string} tagName - The name of the tag.
 * @param {string} contents - The content of the tag.
 * @param {number} index - The index of this tag in the list of similar tags.
 * @returns {string} HTML string for the accordion section.
 */
function createAccordionSection(tagName, contents, index) {
    const id = `${tagName}-${index}`;
    const icon = TAG_ICONS[tagName] || '';
    const langClass = getLanguageClass();

    const formattedContent = tagName === 'solution'
        ? `<code class="syntax-highlight language-${langClass}">${contents}</code>`
        : formatContent(contents);

    return `
        <div class="border-b last:border-b-0">
            <button class="${ACCORDION_HEADER_CLASS} w-full p-4 flex items-center justify-between rounded-t-lg hover:bg-opacity-90 transition-colors duration-200"
                    onclick="toggleAccordion('${id}')"
                    aria-expanded="false"
                    aria-controls="${id}-content">
                <div class="flex items-center space-x-2">
                    ${icon}
                    <span class="text-lg font-medium">${tagName}</span>
                    ${index > 0 ? `<span class="text-sm">(${index + 1})</span>` : ''}
                </div>
                <svg class="w-5 h-5 transform transition-transform duration-200" id="${id}-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/>
                </svg>
            </button>
            <div class="${ACCORDION_CONTENT_CLASS} hidden p-4" id="${id}-content">
                <pre class="p-4 rounded-lg overflow-x-auto whitespace-pre-wrap">${formattedContent}</pre>
            </div>
        </div>
    `;
}

/**
 * Formats content by processing special markup.
 * Note that content is already HTML-escaped by the Python backend.
 * @param {string} content - The content to format.
 * @returns {string} Formatted HTML string.
 */
function formatContent(content) {
    const langClass = getLanguageClass();
    content = content.replace(/<code>([\s\S]*?)<\/code>/g, (match, code) =>
        `<code class="syntax-highlight language-${langClass}">${code}</code>`
    );
    content = content.replace(/<function signature>([\s\S]*?)<\/function signature>/g, (match, signature) =>
        `<div class="bg-blue-50 dark:bg-blue-900 p-3 my-2 rounded-lg"><code class="syntax-highlight language-${langClass} font-mono">${signature}</code></div>`
    );
    return content;
}

/**
 * Gets the language class for syntax highlighting based on benchmark data.
 * @returns {string} The language class name.
 */
function getLanguageClass() {
    if (typeof window.benchmarkData !== 'undefined' && window.benchmarkData.language) {
        return window.benchmarkData.language.toLowerCase();
    }
    return 'plaintext';
}

/**
 * Toggles the visibility of an accordion section.
 * @param {string} id - The ID of the accordion section to toggle.
 */
function toggleAccordion(id) {
    const content = document.getElementById(`${id}-content`);
    const icon = document.getElementById(`${id}-icon`);
    const header = icon.parentElement;
    const isHidden = content.classList.contains('hidden');

    content.classList.toggle('hidden');
    icon.style.transform = isHidden ? 'rotate(180deg)' : 'rotate(0deg)';
    header.setAttribute('aria-expanded', String(isHidden));
}

/**
 * Toggles all accordion sections in the structured prompt.
 * @param {boolean} expand - Whether to expand (true) or collapse (false) sections.
 */
function toggleAllPrompts(expand) {
    const allContents = document.querySelectorAll(`${STRUCTURED_PROMPT_SELECTOR} .${ACCORDION_CONTENT_CLASS}`);
    const allIcons = document.querySelectorAll(`${STRUCTURED_PROMPT_SELECTOR} [id$="-icon"]`);
    const allHeaders = document.querySelectorAll(`${STRUCTURED_PROMPT_SELECTOR} .${ACCORDION_HEADER_CLASS}`);

    const action = expand ? 'remove' : 'add';
    const rotation = expand ? 'rotate(180deg)' : 'rotate(0deg)';

    allContents.forEach(content => content.classList[action]('hidden'));
    allIcons.forEach(icon => icon.style.transform = rotation);
    allHeaders.forEach(header => header.setAttribute('aria-expanded', String(expand)));
}

document.addEventListener('DOMContentLoaded', () => {
    const rawPrompt = document.querySelector('pre').textContent;
    const tags = parsePromptTags(rawPrompt);

    const structuredPromptDiv = document.getElementById('structured-prompt');
    structuredPromptDiv.innerHTML = tags.map((tag, index) =>
        createAccordionSection(tag.type, tag.content, index)
    ).join('');

    const expandAllBtn = document.getElementById('prompts-expand-all');
    const collapseAllBtn = document.getElementById('prompts-collapse-all');

    if (expandAllBtn) {
        expandAllBtn.addEventListener('click', () => toggleAllPrompts(true));
    }
    if (collapseAllBtn) {
        collapseAllBtn.addEventListener('click', () => toggleAllPrompts(false));
    }
});
