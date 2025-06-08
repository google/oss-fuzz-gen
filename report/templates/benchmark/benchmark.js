function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Function to parse prompt tags, preserving order
function parsePromptTags(rawPrompt) {
    const tags = [];
    // Only match system, instruction, task, and solution tags
    const tagRegex = /<(system|instruction|task|solution)>([\s\S]*?)<\/\1>/g;
    let match;

    while ((match = tagRegex.exec(rawPrompt)) !== null) {
        const [_, tagName, content] = match;
        const processedContent = tagName === 'solution' ? content : content.trim();
        tags.push({
            type: tagName,
            content: processedContent
        });
    }

    return tags;
}

function createAccordionSection(tagName, contents, index) {
    const id = `${tagName}-${index}`;
    const icon = getTagIcon(tagName);
    const bgColor = getTagColor(tagName);
    const formattedContent = tagName === 'solution' 
        ? `<code class="syntax-highlight language-${getLanguageClass()}">${escapeHtml(contents)}</code>`
        : formatContent(contents);

    return `
        <div class="border-b last:border-b-0 dark:border-gray-700">
            <button class="accordion-header w-full p-4 flex items-center justify-between ${bgColor} rounded-t-lg hover:bg-opacity-90 transition-colors duration-200"
                    onclick="toggleAccordion('${id}')"
                    aria-expanded="false"
                    aria-controls="${id}-content">
                <div class="flex items-center space-x-2">
                    ${icon}
                    <span class="text-lg font-medium">${tagName}</span>
                    ${index > 0 ? `<span class="text-sm text-gray-500 dark:text-gray-400">(${index + 1})</span>` : ''}
                </div>
                <svg class="w-5 h-5 transform transition-transform duration-200" id="${id}-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/>
                </svg>
            </button>
            <div class="accordion-content hidden p-4 bg-white dark:bg-gray-800" id="${id}-content">
                <pre class="bg-gray-50 dark:bg-gray-900 p-4 rounded-lg overflow-x-auto whitespace-pre-wrap">${formattedContent}</pre>
            </div>
        </div>
    `;
}

function getTagIcon(tagName) {
    const icons = {
        system: '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/></svg>',
        instruction: '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253"/></svg>',
        code: '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"/></svg>',
        task: '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"/></svg>',
        solution: '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>'
    };
    return icons[tagName] || '';
}

function getTagColor(tagName) {
    const colors = {
        system: 'bg-blue-100 dark:bg-blue-900',
        instruction: 'bg-green-100 dark:bg-green-900',
        code: 'bg-yellow-100 dark:bg-yellow-900',
        task: 'bg-purple-100 dark:bg-purple-900',
        solution: 'bg-red-100 dark:bg-red-900'
    };
    return colors[tagName] || 'bg-gray-100 dark:bg-gray-900';
}

function formatContent(content) {
    let formatted = content;
    formatted = escapeHtml(formatted);
    formatted = formatCodeBlocks(formatted);
    formatted = formatFunctionSignature(formatted);
    return formatted;
}

function formatCodeBlocks(content) {
    return content.replace(/<code>([\s\S]*?)<\/code>/g, (match, code) => {
        return `<code class="syntax-highlight language-${getLanguageClass()}">${code}</code>`;
    });
}

function formatFunctionSignature(content) {
    return content.replace(/<function signature>([\s\S]*?)<\/function signature>/g, (match, signature) => {
        return `<div class="bg-blue-50 dark:bg-blue-900 p-3 my-2 rounded-lg"><code class="syntax-highlight language-${getLanguageClass()} font-mono">${signature}</code></div>`;
    });
}

function getLanguageClass() {
    if (typeof window.benchmarkData !== 'undefined' && window.benchmarkData.language) {
        return window.benchmarkData.language.toLowerCase();
    }
    return 'plaintext';
}

function toggleAccordion(id) {
    const content = document.getElementById(`${id}-content`);
    const icon = document.getElementById(`${id}-icon`);
    const header = icon.parentElement;

    content.classList.toggle('hidden');
    icon.style.transform = content.classList.contains('hidden') ? 'rotate(0deg)' : 'rotate(180deg)';
    header.setAttribute('aria-expanded', !content.classList.contains('hidden'));
}

function expandAllPrompts() {
    const allContents = document.querySelectorAll('#structured-prompt .accordion-content');
    const allIcons = document.querySelectorAll('#structured-prompt [id$="-icon"]');
    const allHeaders = document.querySelectorAll('#structured-prompt .accordion-header');

    allContents.forEach(content => content.classList.remove('hidden'));
    allIcons.forEach(icon => icon.style.transform = 'rotate(180deg)');
    allHeaders.forEach(header => header.setAttribute('aria-expanded', 'true'));
}

function collapseAllPrompts() {
    const allContents = document.querySelectorAll('#structured-prompt .accordion-content');
    const allIcons = document.querySelectorAll('#structured-prompt [id$="-icon"]');
    const allHeaders = document.querySelectorAll('#structured-prompt .accordion-header');

    allContents.forEach(content => content.classList.add('hidden'));
    allIcons.forEach(icon => icon.style.transform = 'rotate(0deg)');
    allHeaders.forEach(header => header.setAttribute('aria-expanded', 'false'));
}

// Process the prompt when the document loads
document.addEventListener('DOMContentLoaded', () => {
    const rawPrompt = document.querySelector('pre').textContent;
    const tags = parsePromptTags(rawPrompt);

    const structuredPromptDiv = document.getElementById('structured-prompt');
    let structuredHtml = '';

    tags.forEach((tag, index) => {
        structuredHtml += createAccordionSection(tag.type, tag.content, index);
    });

    structuredPromptDiv.innerHTML = structuredHtml;

    const expandAllBtn = document.getElementById('prompts-expand-all');
    const collapseAllBtn = document.getElementById('prompts-collapse-all');

    if (expandAllBtn) {
        expandAllBtn.addEventListener('click', expandAllPrompts);
    }
    if (collapseAllBtn) {
        collapseAllBtn.addEventListener('click', collapseAllPrompts);
    }
});