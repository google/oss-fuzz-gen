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

const BASE_SEARCH_MIN_LENGTH = 2;
const BASE_SEARCH_DEBOUNCE_MS = 300;
const BASE_RESULTS_PER_PAGE = 10;
const BASE_MAX_PAGINATION_BUTTONS = 5;

const BASE_SEARCH_FIELD_WEIGHTS = {
    SAMPLE_ID: 10,
    CRASH_DETAILS: 8,
    BENCHMARK_ID: 5,
    PROJECT_NAME: 3,
    TRIAGE: 1,
    TRIAGER_PROMPT: 1
};

const BASE_ELEMENT_IDS = {
    SEARCH_INPUT: 'searchInput',
    SEARCH_RESULTS: 'searchResults',
    SEARCH_RESULTS_BODY: 'searchResultsBody',
    SEARCH_RESULTS_COUNT: 'searchResultsCount',
    UNIFIED_DATA: 'unified-data',
    TOC_TREE: 'toc-tree',
    TOC: 'toc',
    TOC_TOGGLE: 'tocToggle'
};

const BASE_CSS_CLASSES = {
    PRETTIFY_BENCHMARK: 'prettify-benchmark-name',
    TOC_SECTION: 'toc-section',
    TOC_SUBSECTION: 'toc-subsection',
    TOC_ITEM: 'toc-item',
    TOC_LINK: 'toc-link'
};

/**
 * Removes the output prefix from benchmark names for cleaner display.
 * @param {string} name - The full benchmark name.
 * @returns {string} The prettified benchmark name without the output prefix.
 */
function prettifyBenchmarkName(name) {
    return name.replace(/^output-[^-]+-/, '');
}

/**
 * Searches through unified sample data using regex pattern matching with weighted scoring.
 * @param {string} searchTerm - The search term to match against sample data.
 * @param {Object} unifiedData - The unified data structure containing all project/benchmark/sample information.
 * @returns {Array<Object>|Object} Array of search results sorted by score, or error object if regex is invalid.
 */
function searchSamples(searchTerm, unifiedData) {
    if (!searchTerm || searchTerm.length < BASE_SEARCH_MIN_LENGTH) {
        return [];
    }

    const results = [];
    let searchPattern;

    try {
        searchPattern = new RegExp(searchTerm.toLowerCase(), 'g');
    } catch (e) {
        return { error: true, message: e.message, pattern: searchTerm };
    }

    for (const projectName in unifiedData) {
        const project = unifiedData[projectName];
        if (project.benchmarks) {
            for (const benchmarkId in project.benchmarks) {
                const benchmark = project.benchmarks[benchmarkId];
                if (benchmark.samples) {
                    benchmark.samples.forEach(sample => {
                        const fields = [
                            { text: sample.sample || '', weight: BASE_SEARCH_FIELD_WEIGHTS.SAMPLE_ID, name: 'Sample ID' },
                            { text: sample.crash_details || '', weight: BASE_SEARCH_FIELD_WEIGHTS.CRASH_DETAILS, name: 'Crash Details' },
                            { text: benchmarkId, weight: BASE_SEARCH_FIELD_WEIGHTS.BENCHMARK_ID, name: 'Benchmark ID' },
                            { text: projectName, weight: BASE_SEARCH_FIELD_WEIGHTS.PROJECT_NAME, name: 'Project Name' },
                            { text: sample.triage || '', weight: BASE_SEARCH_FIELD_WEIGHTS.TRIAGE, name: 'Triage' },
                            { text: sample.triager_prompt || '', weight: BASE_SEARCH_FIELD_WEIGHTS.TRIAGER_PROMPT, name: 'Triager Prompt' }
                        ];

                        let score = 0;
                        let hasMatch = false;
                        const matchedFields = [];

                        fields.forEach(field => {
                            const fieldText = field.text.toLowerCase();
                            const matches = fieldText.match(searchPattern);
                            if (matches) {
                                hasMatch = true;
                                let fieldScore = field.weight * matches.length;

                                if (fieldText.includes(searchTerm.toLowerCase())) {
                                    fieldScore += field.weight * 2;
                                }

                                score += fieldScore;
                                matchedFields.push({
                                    name: field.name,
                                    matches: matches.length,
                                    score: fieldScore
                                });
                            }
                        });

                        if (hasMatch) {
                            results.push({
                                projectName,
                                benchmarkId,
                                sampleId: sample.sample || '',
                                sample,
                                score,
                                matchedFields
                            });
                        }
                    });
                }
            }
        }
    }

    results.sort((a, b) => b.score - a.score);
    return results;
}

/**
 * Gets the relative URL path based on current page context.
 * @returns {string} The relative path prefix.
 */
function getRelativePath() {
    return window.BASE_RELATIVE_PATH || '';
}

/**
 * Renders search results with pagination in the search results container.
 * @param {Array<Object>} results - Array of search result objects with sample data and scores.
 * @param {number} currentPage - The current page number to display.
 */
function renderSearchResults(results, currentPage = 1) {
    const searchResultsContainer = document.getElementById(BASE_ELEMENT_IDS.SEARCH_RESULTS);
    const searchResultsBody = document.getElementById(BASE_ELEMENT_IDS.SEARCH_RESULTS_BODY);
    const searchResultsCount = document.getElementById(BASE_ELEMENT_IDS.SEARCH_RESULTS_COUNT);

    if (results.length === 0) {
        searchResultsContainer.classList.add('hidden');
        return;
    }

    const totalPages = Math.ceil(results.length / BASE_RESULTS_PER_PAGE);
    const startIndex = (currentPage - 1) * BASE_RESULTS_PER_PAGE;
    const endIndex = startIndex + BASE_RESULTS_PER_PAGE;
    const pageResults = results.slice(startIndex, endIndex);

    searchResultsCount.textContent = `${results.length} sample${results.length !== 1 ? 's' : ''} found (showing page ${currentPage} of ${totalPages})`;

    const paginationHtml = totalPages > 1 ? `
        <div class="pagination-controls flex items-center justify-center gap-2 mb-4 p-4 border rounded-lg">
            <button onclick="navigateToPage(${currentPage - 1})"
                    ${currentPage === 1 ? 'disabled' : ''}
                    class="px-3 py-1 border rounded ${currentPage === 1 ? 'opacity-50 cursor-not-allowed' : 'hover:bg-gray-100 dark:hover:bg-gray-700'}">
                « Previous
            </button>

            ${Array.from({length: Math.min(BASE_MAX_PAGINATION_BUTTONS, totalPages)}, (_, i) => {
                let pageNum;
                if (totalPages <= BASE_MAX_PAGINATION_BUTTONS) {
                    pageNum = i + 1;
                } else if (currentPage <= 3) {
                    pageNum = i + 1;
                } else if (currentPage >= totalPages - 2) {
                    pageNum = totalPages - 4 + i;
                } else {
                    pageNum = currentPage - 2 + i;
                }

                return `
                    <button onclick="navigateToPage(${pageNum})"
                            class="px-3 py-1 border rounded ${pageNum === currentPage ? 'bg-blue-500 text-white' : 'hover:bg-gray-100 dark:hover:bg-gray-700'}">
                        ${pageNum}
                    </button>
                `;
            }).join('')}

            <button onclick="navigateToPage(${currentPage + 1})"
                    ${currentPage === totalPages ? 'disabled' : ''}
                    class="px-3 py-1 border rounded ${currentPage === totalPages ? 'opacity-50 cursor-not-allowed' : 'hover:bg-gray-100 dark:hover:bg-gray-700'}">
                Next »
            </button>
        </div>
    ` : '';

    const relativePath = getRelativePath();
    searchResultsBody.innerHTML = paginationHtml + pageResults.map(result => {
        const sampleUrl = `${relativePath}sample/${encodeURIComponent(result.benchmarkId)}/${encodeURIComponent(result.sampleId)}.html`;
        const benchmarkUrl = `${relativePath}benchmark/${encodeURIComponent(result.benchmarkId)}/index.html`;

        const additionalInfo = [];

        if (result.sample.crash_symptom) {
            additionalInfo.push(`<span class="font-medium">Crash Symptom:</span> ${result.sample.crash_symptom}`);
        }

        if (result.sample.triage) {
            const triagePreview = result.sample.triage.length > 100
                ? result.sample.triage.substring(0, 100) + '...'
                : result.sample.triage;
            additionalInfo.push(`<span class="font-medium">Triage:</span> ${triagePreview}`);
        }

        return `
            <div class="border rounded-lg p-4">
                <div class="flex justify-between items-start mb-2">
                    <h2 class="signature">
                        <a href="${sampleUrl}" class="hover:underline">
                            <span class="${BASE_CSS_CLASSES.PRETTIFY_BENCHMARK}">${result.benchmarkId}/${result.sampleId}</span>
                        </a>
                    </h2>
                    <div class="text-xs px-2 py-1 rounded">
                        Score: ${result.score}
                    </div>
                </div>
                <div class="text-sm mb-2">
                    <span class="font-medium">Project:</span> ${result.projectName} |
                    <span class="font-medium">Benchmark:</span>
                    <a href="${benchmarkUrl}" class="hover:underline">
                        <span class="${BASE_CSS_CLASSES.PRETTIFY_BENCHMARK}">${result.benchmarkId}</span>
                    </a>
                </div>
                <div class="text-sm mb-2">
                    <span class="font-medium">Matches in:</span>
                    ${result.matchedFields.map(field =>
                        `<span class="inline-block px-2 py-1 bg-blue-100 text-blue-800 rounded text-xs mr-1 mb-1">
                            ${field.name} (${field.matches} ${field.matches > 1 ? 'matches' : 'match'})
                        </span>`
                    ).join('')}
                </div>
                ${additionalInfo.length > 0 ? `
                <div class="text-sm mb-3 space-y-1">
                    ${additionalInfo.map(info => `<div>${info}</div>`).join('')}
                </div>
                ` : ''}
                <div class="flex gap-4 text-xs">
                    <span>Coverage: ${(result.sample.total_coverage || 0).toFixed(2)}%</span>
                    <span>Line Diff: ${(result.sample.total_line_coverage_diff || 0).toFixed(2)}%</span>
                </div>
            </div>
        `;
    }).join('');

    searchResultsContainer.classList.remove('hidden');

    document.querySelectorAll(`.search-results-body .${BASE_CSS_CLASSES.PRETTIFY_BENCHMARK}`).forEach(el => {
        el.textContent = prettifyBenchmarkName(el.textContent);
    });
}

/**
 * Renders an error message when an invalid regex pattern is entered.
 * @param {Object} error - Error object containing error message and pattern.
 */
function renderRegexError(error) {
    const searchResultsContainer = document.getElementById(BASE_ELEMENT_IDS.SEARCH_RESULTS);
    const searchResultsBody = document.getElementById(BASE_ELEMENT_IDS.SEARCH_RESULTS_BODY);

    searchResultsBody.innerHTML = `
        <div class="border rounded-lg p-4 bg-red-50 border-red-200">
            <div class="flex items-center mb-2">
                <svg class="w-5 h-5 text-red-50 mr-2" fill="currentColor" viewBox="0 0 20 20">
                    <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clip-rule="evenodd"></path>
                </svg>
                <span class="font-medium text-red-50">Invalid regex pattern</span>
            </div>
            <p class="text-sm">
                Pattern: <code class="bg-red-200 px-1 rounded text-black">${error.pattern}</code>
            </p>
            <p class="text-sm mt-2">
                Error: ${error.message}
            </p>
        </div>
    `;

    searchResultsContainer.classList.remove('hidden');
}

/**
 * Navigates to a specific page in the search results pagination.
 * @param {number} page - The page number to navigate to.
 */
function navigateToPage(page) {
    if (page < 1 || page > Math.ceil(window.currentSearchResults.length / BASE_RESULTS_PER_PAGE)) return;
    window.currentPage = page;
    renderSearchResults(window.currentSearchResults, window.currentPage);
}

/**
 * Initializes the search functionality.
 */
function initializeSearch() {
    const searchInput = document.getElementById(BASE_ELEMENT_IDS.SEARCH_INPUT);
    const searchResults = document.getElementById(BASE_ELEMENT_IDS.SEARCH_RESULTS);
    if (!searchInput || !searchResults) return;

    let searchTimeout;
    let unifiedData = {};
    const unifiedDataElement = document.getElementById(BASE_ELEMENT_IDS.UNIFIED_DATA);

    if (unifiedDataElement) {
        try {
            unifiedData = JSON.parse(unifiedDataElement.textContent);
            console.log('Unified data loaded:', unifiedData);
        } catch (e) {
            console.warn('Could not parse unified data for search:', e);
        }
    } else {
        console.warn('No unified data element found');
    }

    window.currentSearchResults = [];
    window.currentPage = 1;

    searchInput.addEventListener('input', (event) => {
        clearTimeout(searchTimeout);
        const searchTerm = event.target.value.trim();

        if (searchTerm.length < BASE_SEARCH_MIN_LENGTH) {
            searchResults.classList.add('hidden');
            window.currentSearchResults = [];
            window.currentPage = 1;
            return;
        }

        searchTimeout = setTimeout(() => {
            const results = searchSamples(searchTerm, unifiedData);
            if (results.error) {
                renderRegexError(results);
                window.currentSearchResults = [];
            } else {
                window.currentSearchResults = results;
                window.currentPage = 1;
                renderSearchResults(results, window.currentPage);
            }
        }, BASE_SEARCH_DEBOUNCE_MS);
    });
}

/**
 * Builds the table of contents tree from section headers.
 */
function buildTOC() {
    const tocTree = document.getElementById(BASE_ELEMENT_IDS.TOC_TREE);
    if (!tocTree) return;

    const sections = document.querySelectorAll(`.${BASE_CSS_CLASSES.TOC_SECTION}`);
    sections.forEach((section, index) => {
        const sectionLi = document.createElement('li');
        const sectionLink = document.createElement('a');
        const sectionTitle = section.querySelector('.text-lg.font-bold');
        sectionLink.textContent = sectionTitle.textContent.trim();
        sectionLink.href = `#section-${index}`;
        sectionLink.className = `${BASE_CSS_CLASSES.TOC_LINK} ${BASE_CSS_CLASSES.TOC_SECTION}`;
        section.id = `section-${index}`;
        sectionLi.appendChild(sectionLink);

        const subsectionButtons = section.querySelectorAll(`.${BASE_CSS_CLASSES.TOC_SUBSECTION}`);
        if (subsectionButtons.length > 0) {
            const subsectionsUl = document.createElement('ul');

            subsectionButtons.forEach(subsectionBtn => {
                const subsectionName = subsectionBtn.textContent.trim();
                const subsectionLi = document.createElement('li');
                const subsectionLink = document.createElement('a');
                subsectionLink.textContent = subsectionName;
                subsectionLink.href = `#subsection-${subsectionName}`;
                subsectionLink.className = `${BASE_CSS_CLASSES.TOC_LINK} ${BASE_CSS_CLASSES.TOC_SUBSECTION}`;
                subsectionLi.appendChild(subsectionLink);

                const subsectionRow = subsectionBtn.closest('tr');
                const itemsContainer = subsectionRow ? subsectionRow.nextElementSibling : null;

                if (itemsContainer) {
                    const itemButtons = itemsContainer.querySelectorAll(`button.${BASE_CSS_CLASSES.TOC_ITEM}`);
                    const itemLinks = itemsContainer.querySelectorAll(`pre.signature.${BASE_CSS_CLASSES.TOC_ITEM} a`);

                    if (itemButtons.length > 0 || itemLinks.length > 0) {
                        const itemsUl = document.createElement('ul');

                        itemButtons.forEach(itemBtn => {
                            const itemLi = document.createElement('li');
                            const itemLink = document.createElement('a');
                            const itemText = itemBtn.querySelector('pre.signature a') ?
                                itemBtn.querySelector('pre.signature a').textContent.trim() :
                                itemBtn.textContent.trim();
                            itemLink.textContent = itemText;
                            itemLink.href = `#item-${itemText}`;
                            itemLink.className = `${BASE_CSS_CLASSES.TOC_LINK} ${BASE_CSS_CLASSES.TOC_ITEM} ${BASE_CSS_CLASSES.PRETTIFY_BENCHMARK}`;
                            itemLink.addEventListener('click', (e) => {
                                e.preventDefault();
                                const itemRow = itemBtn.closest('tr');
                                if (itemRow) {
                                    itemRow.scrollIntoView({ behavior: 'smooth' });
                                    const containers = itemRow.closest('[x-ref^="benchmarks_"], [x-ref^="project_"]');
                                    if (containers && containers.classList.contains('hidden')) {
                                        containers.classList.remove('hidden');
                                    }
                                }
                            });
                            itemLi.appendChild(itemLink);
                            itemsUl.appendChild(itemLi);
                        });

                        itemLinks.forEach(itemLinkEl => {
                            const itemLi = document.createElement('li');
                            const itemLink = document.createElement('a');
                            itemLink.textContent = itemLinkEl.textContent.trim();
                            itemLink.href = `#item-${itemLinkEl.textContent.trim()}`;
                            itemLink.className = `${BASE_CSS_CLASSES.TOC_LINK} ${BASE_CSS_CLASSES.TOC_ITEM} ${BASE_CSS_CLASSES.PRETTIFY_BENCHMARK}`;
                            itemLink.addEventListener('click', (e) => {
                                e.preventDefault();
                                const itemRow = itemLinkEl.closest('tr');
                                if (itemRow) {
                                    itemRow.scrollIntoView({ behavior: 'smooth' });
                                    const containers = itemRow.closest('[x-ref^="benchmarks_"], [x-ref^="project_"]');
                                    if (containers && containers.classList.contains('hidden')) {
                                        containers.classList.remove('hidden');
                                    }
                                }
                            });
                            itemLi.appendChild(itemLink);
                            itemsUl.appendChild(itemLi);
                        });

                        subsectionLi.appendChild(itemsUl);
                    }
                }
                subsectionsUl.appendChild(subsectionLi);
            });
            sectionLi.appendChild(subsectionsUl);
        }
        tocTree.appendChild(sectionLi);
    });
}

/**
 * Initializes TOC toggle functionality.
 */
function initializeTOCToggle() {
    const toc = document.getElementById(BASE_ELEMENT_IDS.TOC);
    const tocToggle = document.getElementById(BASE_ELEMENT_IDS.TOC_TOGGLE);

    if (!toc || !tocToggle) return;

    tocToggle.addEventListener('click', () => {
        toc.classList.toggle('open');
        tocToggle.classList.toggle('open');
    });

    document.addEventListener('click', (e) => {
        if (!toc.contains(e.target) && !tocToggle.contains(e.target) && toc.classList.contains('open')) {
            toc.classList.remove('open');
            tocToggle.classList.remove('open');
        }
    });
}

/**
 * Initializes syntax highlighting for all code blocks.
 */
function initializeSyntaxHighlighting() {
    if (!window.hljs || typeof window.hljs.highlightAll !== 'function') return;

    window.hljs.highlightAll();

    const observer = new MutationObserver((mutations) => {
        for (const mutation of mutations) {
            for (const node of mutation.addedNodes) {
                if (!(node instanceof HTMLElement)) continue;
                node.querySelectorAll('pre code:not(.hljs)').forEach((el) => {
                    try {
                        window.hljs.highlightElement(el);
                    } catch (error) {
                        console.warn('Failed to highlight element:', error);
                    }
                });
            }
        }
    });

    try {
        observer.observe(document.body, { childList: true, subtree: true });
    } catch (error) {
        console.warn('Failed to observe DOM mutations:', error);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll(`.${BASE_CSS_CLASSES.PRETTIFY_BENCHMARK}`).forEach(el => {
        el.textContent = prettifyBenchmarkName(el.textContent);
    });

    initializeSearch();
    buildTOC();
    initializeTOCToggle();
});

window.addEventListener('DOMContentLoaded', () => {
    initializeSyntaxHighlighting();
});

