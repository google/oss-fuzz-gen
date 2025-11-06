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

const MIN_CONTAINER_WIDTH = 300;
const MIN_CONTAINER_HEIGHT = 220;
const CONTAINER_PADDING = 20;

const LEGEND_MAX_WIDTH = 200;
const LEGEND_WIDTH_RATIO = 0.25;
const LEGEND_HEIGHT_OFFSET = 40;
const HOVER_PANEL_MIN_WIDTH = 200;
const HOVER_PANEL_WIDTH_OFFSET = 250;
const PIE_CHART_OFFSET = 32;
const PIE_AVAILABLE_WIDTH_RATIO = 0.6;
const PIE_MAX_SIZE = 350;
const PIE_SIZE_OFFSET = 80;
const PIE_RADIUS_OFFSET = 20;
const PIE_MIN_RADIUS = 80;
const PIE_MIN_HEIGHT = 200;
const EMPTY_PIE_HEIGHT = 200;

const TIME_UNITS = {
	SECONDS: { code: 's', label: 'Seconds', divisor: 1 },
	MINUTES: { code: 'm', label: 'Minutes', divisor: 60 },
	HOURS: { code: 'h', label: 'Hours', divisor: 3600 }
};

const COLORS = {
	CYCLES_PROJECT: '#3b82f6',
	DURATION_PROJECT: '#9ca3af',
	CYCLES_BENCH: '#1d4ed8',
	DURATION_BENCH: '#6b7280',
	EXISTING_COVERAGE: '#94a3b8',
	NEW_COVERAGE: '#3b82f6',
	CRASH_REASON: '#f59e0b',
	PIE_STROKE: '#ffffff',
	FALLBACK_PALETTE: ['#3b82f6','#22c55e','#ef4444','#f59e0b','#8b5cf6','#06b6d4','#84cc16','#e11d48','#64748b','#a855f7']
};

const ELEMENT_IDS = {
	UNIFIED_DATA: 'unified-data',
	PROJECT_SUMMARY_TABLE: 'project-summary-table',
	COVERAGE_CHART: 'coverage-chart',
	CRASH_REASONS_CHART: 'crash-reasons-chart',
	CYCLES_PROJECTS_CHART: 'cycles-projects-chart',
	DURATION_PROJECTS_CHART: 'duration-projects-chart',
	CYCLES_BENCHMARKS_CHART: 'cycles-benchmarks-chart',
	DURATION_BENCHMARKS_CHART: 'duration-benchmarks-chart',
	PROJECT_SUMMARY_EXPAND: 'project-summary-expand-all',
	PROJECT_SUMMARY_COLLAPSE: 'project-summary-collapse-all',
	CRASHES_EXPAND: 'crashes-expand-all',
	CRASHES_COLLAPSE: 'crashes-collapse-all',
	STRUCTURED_PROMPT: 'structured-prompt',
	COVERAGE_NORMALIZED: 'coverage-normalized'
};

const SELECTORS = {
	BENCHMARKS: '[x-ref^="benchmarks_"]',
	PROJECT_CRASHES: '[x-ref^="project_"]',
	SAMPLE_CRASHES: '[x-ref^="samples_"]'
};

const COLUMN_NAMES = {
	NEW_COVERED_LINES: 'OSS-Fuzz-Gen new covered lines',
	EXISTING_COVERED_LINES: 'Existing covered lines',
	TOTAL_PROJECT_LINES: 'Total project lines',
	SUCCESSFUL_BENCHMARKS: 'Successful benchmarks',
	BUILD_RATE: 'Build Rate'
};

const TRUNCATE_DEFAULT_LENGTH = 20;

// Chart margins
const MARGIN_LEFT_MIN = 120;
const MARGIN_LEFT_MAX = 400;
const MARGIN_LEFT_MULTIPLIER = 8;
const MARGIN_LEFT_BASE = 24;


/**
 * Gets the appropriate bar chart Y function from Plot library with fallback compatibility.
 * @returns {Function|null} The bar Y function or null if unavailable.
 */
function getBarY() {
	if (Plot.barY) return Plot.barY;
	if (Plot.BarY) return Plot.BarY;
	if (Plot.rectY) {
		return (data, opts) => {
			const { x, y, fill, title } = opts || {};
			return Plot.rectY(data, { x, y2: y, y1: 0, fill, title });
		};
	}
	return null;
}

/**
 * Reads and parses unified data from the DOM.
 * @returns {Object|null} Parsed JSON data or null if unavailable.
 */
function readUnifiedData() {
	const el = document.getElementById(ELEMENT_IDS.UNIFIED_DATA);
	if (!el) return null;
	try {
		return JSON.parse(el.textContent);
	} catch (error) {
		console.error('Failed to parse unified data:', error);
		return null;
	}
}

/**
 * Gets the size of a container element with fallback values.
 * @param {HTMLElement} el - The container element.
 * @param {number} fallbackW - Fallback width.
 * @param {number} fallbackH - Fallback height.
 * @returns {{width: number, height: number}} Container dimensions.
 */
function containerSize(el, fallbackW = 800, fallbackH = 300) {
	if (!el) return { width: fallbackW, height: fallbackH };
	const rect = el.getBoundingClientRect();
	const width = Math.max(MIN_CONTAINER_WIDTH, Math.floor(rect.width - CONTAINER_PADDING));
	const height = Math.max(MIN_CONTAINER_HEIGHT, Math.floor(rect.height - CONTAINER_PADDING));
	return { width, height };
}

/**
 * Sets the height of a container element.
 * @param {HTMLElement} el - The element to resize.
 * @param {number} height - The height in pixels.
 */
function setContainerHeight(el, height) {
	if (el) {
		el.style.height = `${height}px`;
	}
}

/**
 * Appends a title element to a container.
 * @param {HTMLElement} el - The container element.
 * @param {string} text - The title text.
 */
function appendTitle(el, text) {
	const title = document.createElement('div');
	title.textContent = text;
	title.style.fontWeight = '600';
	title.style.marginBottom = '8px';
	el.appendChild(title);
}

/**
 * Truncates a label string to a maximum length.
 * @param {string} str - The string to truncate.
 * @param {number} max - Maximum length before truncation.
 * @returns {string} Truncated string with ellipsis if needed.
 */
function truncateLabel(str, max = TRUNCATE_DEFAULT_LENGTH) {
	if (!str) return '';
	if (str.length <= max) return str;
	return str.slice(0, max - 1) + '…';
}

/**
 * Extracts bug type from AddressSanitizer crash symptom string.
 * @param {string} symptom - The crash symptom string.
 * @returns {string} Extracted bug type in lowercase.
 */
function extractBugType(symptom) {
	if (!symptom || typeof symptom !== 'string') return '';
	const betweenMatch = symptom.match(/AddressSanitizer:\s*(.+?)\s+on\b/i);
	if (betweenMatch) return betweenMatch[1].trim().toLowerCase();
	const fallback = symptom.match(/ERROR:\s*AddressSanitizer:\s*([A-Za-z0-9_-]+)/i);
	return fallback ? fallback[1].toLowerCase() : '';
}

/**
 * Dynamically adds a 'Build rate' column to the project summary table.
 */
function addProjectBuildRateColumn() {
	const table = document.getElementById(ELEMENT_IDS.PROJECT_SUMMARY_TABLE);
	if (!table) return;
	const theadRow = table.querySelector('thead tr');
	if (!theadRow) return;
	const ths = Array.from(theadRow.querySelectorAll('th'));
	let insertIdx = -1;
	for (let i = 0; i < ths.length; i++) {
		const txt = (ths[i].textContent || '').trim().toLowerCase();
		if (txt.includes(COLUMN_NAMES.SUCCESSFUL_BENCHMARKS.toLowerCase())) { insertIdx = i + 1; break; }
	}
	if (insertIdx === -1) return;

	const newTh = document.createElement('th');
	newTh.setAttribute('data-sort-number', '');
	newTh.textContent = COLUMN_NAMES.BUILD_RATE;
	const refTh = ths[insertIdx] || null;
	if (refTh) theadRow.insertBefore(newTh, refTh); else theadRow.appendChild(newTh);

	const rows = Array.from(table.querySelectorAll(':scope > tbody > tr'));
	rows.forEach(row => {
		if (row.classList.contains('project-data-row')) {
			const cells = Array.from(row.querySelectorAll('td'));
			const total = parseFloat(cells[2]?.dataset.sortValue || cells[2]?.textContent) || 0;
			const successful = parseFloat(cells[3]?.dataset.sortValue || cells[3]?.textContent) || 0;
			const rate = total > 0 ? (successful / total) * 100 : 0;
			const td = document.createElement('td');
			td.dataset.sortValue = rate.toFixed(2);
			td.textContent = rate.toFixed(2);
			const refCell = cells[insertIdx] || null;
			if (refCell) row.insertBefore(td, refCell); else row.appendChild(td);
		} else if (row.classList.contains('project-benchmarks-container-row')) {
			const cell = row.querySelector('td[colspan]');
			if (cell) {
				const curr = parseInt(cell.getAttribute('colspan') || '0');
				if (!isNaN(curr) && curr > 0) cell.setAttribute('colspan', String(curr + 1));
			}
		} else {
			const cells = Array.from(row.querySelectorAll('td'));
			if (!cells.length) return;
			const td = document.createElement('td');
			td.textContent = '-';
			const refCell = cells[insertIdx] || null;
			if (refCell) row.insertBefore(td, refCell); else row.appendChild(td);
		}
	});
}

/**
 * Gets the column index in the project summary table by searching for a substring.
 * @param {string} substr - The substring to search for in column headers.
 * @returns {number} Column index or -1 if not found.
 */
function getProjectSummaryColumnIndex(substr) {
	const table = document.getElementById(ELEMENT_IDS.PROJECT_SUMMARY_TABLE);
	if (!table) return -1;
	const ths = Array.from(table.querySelectorAll('thead th'));
	for (let i = 0; i < ths.length; i++) {
		const txt = (ths[i].textContent || '').trim().toLowerCase();
		if (txt.includes(substr.toLowerCase())) return i;
	}
	return -1;
}

/**
 * Renders a pie chart showing crash reasons with interactive legend and detail panel.
 * @param {HTMLElement} el - The container element.
 * @param {Array<{reason: string, count: number}>} data - Crash reason data.
 * @param {Object} unified - Unified project data.
 * @returns {boolean} True if rendered successfully, false otherwise.
 */
function renderCrashReasonsPie(el, data, unified) {
	if (typeof d3 === 'undefined') return false;

	while (el.children.length > 1) {
		el.removeChild(el.lastChild);
	}

	const { width, height } = containerSize(el);

	const mainContainer = d3.select(el).append('div')
		.style('display', 'flex')
		.style('height', '100%')
		.style('gap', '16px')
		.style('position', 'relative');

	const legendWidth = Math.min(LEGEND_MAX_WIDTH, width * LEGEND_WIDTH_RATIO);
	const legendContainer = mainContainer.append('div')
		.style('width', `${legendWidth}px`)
		.style('flex-shrink', '0')
		.style('overflow-y', 'auto')
		.style('max-height', `${height - LEGEND_HEIGHT_OFFSET}px`);

	const hoverWidth = Math.max(HOVER_PANEL_MIN_WIDTH, width - legendWidth - HOVER_PANEL_WIDTH_OFFSET);
	const pieContainer = mainContainer.append('div')
		.attr('class', 'pie-chart-container')
		.style('flex', '1')
		.style('display', 'flex')
		.style('align-items', 'center')
		.style('justify-content', 'flex-start')
		.style('min-width', '0');

	const hoverPanel = mainContainer.append('div')
		.attr('class', 'crash-hover-panel')
		.style('width', `${hoverWidth}px`)
		.style('flex-shrink', '0')
		.style('padding', '12px')
		.style('border-radius', '8px')
		.style('border', '1px solid')
		.style('opacity', '1')
		.style('max-height', `${height - LEGEND_HEIGHT_OFFSET}px`)
		.style('overflow', 'hidden')
		.style('display', 'flex')
		.style('flex-direction', 'column');

	const hoverTitle = hoverPanel.append('div')
		.attr('class', 'crash-hover-title')
		.style('font-weight', '600')
		.style('margin-bottom', '8px')
		.style('flex-shrink', '0')
		.text('Click on pie chart to pin');

	const hoverContent = hoverPanel.append('div')
		.attr('class', 'crash-hover-content')
		.style('font-size', '14px')
		.style('flex', '1')
		.style('overflow-y', 'auto')
		.style('min-height', '0');

	const scheme = (d3.schemeTableau10 || d3.schemeCategory10 || []);
	const color = scheme.length ? d3.scaleOrdinal(scheme) : d3.scaleOrdinal().range(COLORS.FALLBACK_PALETTE);
	color.domain(data.map(d=>d.reason));

	data.forEach(d => {
		const item = legendContainer.append('div')
			.style('display','flex')
			.style('align-items','center')
			.style('gap','8px')
			.style('margin-bottom', '6px')
			.style('cursor', 'pointer')
			.style('padding', '4px')
			.style('border-radius', '4px')
			.style('transition', 'background-color 0.2s')
			.on('click', function(event){
				event.stopPropagation();
				showCrashDetails({ data: d });
			});

		item.append('span')
			.style('display','inline-block')
			.style('width','16px')
			.style('height','16px')
			.style('border-radius', '2px')
			.style('background', color(d.reason));

		const textContainer = item.append('div');
		textContainer.append('div')
			.style('font-weight', '500')
			.style('font-size', '14px')
			.text(d.reason);
		textContainer.append('div')
			.style('font-size', '12px')
			.style('color', '#6b7280')
			.text(`${d.count} crashes`);
	});

	const values = data.map(d => d.count || 0);
	const sum = values.reduce((a,b)=>a+b,0);
	if (sum <= 0) {
		pieContainer.append('div').text('No crash reasons');
		setContainerHeight(el, EMPTY_PIE_HEIGHT);
		return true;
	}

	const availableWidth = width - legendWidth - PIE_CHART_OFFSET;
	const pieSize = Math.min(availableWidth * PIE_AVAILABLE_WIDTH_RATIO, height - PIE_SIZE_OFFSET, PIE_MAX_SIZE);
	const maxRadius = Math.min(pieSize / 2 - PIE_RADIUS_OFFSET, pieSize / 2 - PIE_RADIUS_OFFSET);
	const radius = Math.max(PIE_MIN_RADIUS, maxRadius);

	const svg = pieContainer.append('svg')
		.attr('width', pieSize)
		.attr('height', pieSize);

	const g = svg.append('g')
		.attr('transform', `translate(${pieSize/2},${pieSize/2})`);

	const pie = d3.pie().sort(null).value(d => d.count)(data);
	const arc = d3.arc().outerRadius(radius).innerRadius(0);

	/**
	 * Gets detailed crash information for a specific bug reason.
	 * @param {string} reason - The bug type/reason to filter by.
	 * @returns {Array<Object>} Array of crash details.
	 */
	function getCrashDetails(reason) {
		const details = [];
		if (!unified) return details;

		for (const projectName in unified) {
			const project = unified[projectName];
			if (project.benchmarks) {
				for (const benchId in project.benchmarks) {
					const bench = project.benchmarks[benchId];
					if (bench.samples) {
						bench.samples.forEach(s => {
							const bugType = extractBugType((s.crash_symptom || '').trim());
							if (bugType === reason && s.crashes) {
								details.push({
									project: projectName,
									benchmark: benchId,
									sample: s.sample,
									symptom: s.crash_symptom
								});
							}
						});
					}
				}
			}
		}
		return details;
	}

	/**
	 * Displays crash details in the hover panel.
	 * @param {Object} d - Data object containing crash reason and count.
	 */
	function showCrashDetails(d) {
		hoverTitle.text(`${d.data.reason} (${d.data.count} crashes)`);
		const details = getCrashDetails(d.data.reason);
		hoverContent.selectAll('*').remove();
		if (details.length === 0) {
			hoverContent.append('div')
				.attr('class', 'crash-no-details')
				.style('font-style', 'italic')
				.text('No detailed crash info available');
		} else {
			details.forEach(detail => {
				const item = hoverContent.append('div')
					.attr('class', 'crash-detail-item')
					.style('margin-bottom', '8px')
					.style('padding', '6px')
					.style('border-radius', '4px')
					.style('border', '1px solid')
					.style('box-shadow', '0 1px 2px rgba(0,0,0,0.05)');
				const header = item.append('div')
					.attr('class', 'crash-detail-project')
					.style('font-weight', '500')
					.style('font-size', '12px');
				header.append('span').text(`${detail.project}/`);
				const prettyBench = (typeof prettifyBenchmarkName === 'function') ? prettifyBenchmarkName(detail.benchmark) : detail.benchmark;
				header.append('span')
					.attr('class', 'prettify-benchmark-name')
					.text(prettyBench);
				const sampleRow = item.append('div')
					.attr('class', 'crash-detail-sample')
					.style('font-size', '11px');
				const sampleUrl = `sample/${encodeURIComponent(detail.benchmark)}/${encodeURIComponent(detail.sample)}.html`;
				sampleRow.append('a')
					.attr('href', sampleUrl)
					.text(`Sample ${detail.sample}`);

				item
					.style('cursor', 'pointer')
					.attr('tabindex', '0')
					.on('click', function() {
						window.location.href = sampleUrl;
					})
					.on('keydown', function(event) {
						if (event.key === 'Enter' || event.key === ' ') {
							event.preventDefault();
							window.location.href = sampleUrl;
						}
					});
				if (detail.symptom && detail.symptom.length > 50) {
					item.append('div')
						.attr('class', 'crash-detail-symptom')
						.style('font-size', '10px')
						.style('margin-top', '2px')
						.text(detail.symptom.substring(0, 80) + '...');
				}
			});
		}
	}

	g.selectAll('path')
		.data(pie)
		.enter()
		.append('path')
		.attr('d', arc)
		.attr('fill', d => color(d.data.reason))
		.style('cursor', 'pointer')
		.style('stroke', COLORS.PIE_STROKE)
		.style('stroke-width', '2px')
		.on('mouseenter', function(event, d) {
			d3.select(this).style('opacity', '0.8');
		})
		.on('mouseleave', function(event, d) {
			d3.select(this).style('opacity', '1');
		})
		.on('click', function(event, d) {
			showCrashDetails(d);
		});

	setContainerHeight(el, Math.max(PIE_MIN_HEIGHT, pieSize + LEGEND_HEIGHT_OFFSET));

	if (data.length > 0) {
		showCrashDetails({ data: data[0] });
	}
	return true;
}

/**
 * Creates an interactive duration chart with unit selector.
 * @param {HTMLElement} containerEl - Container element.
 * @param {string} title - Chart title.
 * @param {Array<Object>} data - Chart data.
 * @param {string} labelKey - Key for label data.
 * @param {string} valueKey - Key for value data.
 * @param {string} fillColor - Bar fill color.
 * @param {Object} heightConfig - Height configuration object.
 */
function createDurationChart(containerEl, title, data, labelKey, valueKey, fillColor, heightConfig) {
	containerEl.innerHTML = '';
	const titleContainer = document.createElement('div');
	titleContainer.style.display = 'flex';
	titleContainer.style.alignItems = 'center';
	titleContainer.style.gap = '16px';
	titleContainer.style.marginBottom = '8px';
	const titleEl = document.createElement('div');
	titleEl.textContent = title;
	titleEl.style.fontWeight = '600';
	const select = document.createElement('select');
	select.innerHTML = `<option value="${TIME_UNITS.SECONDS.code}">Seconds</option><option value="${TIME_UNITS.MINUTES.code}" selected>Minutes</option><option value="${TIME_UNITS.HOURS.code}">Hours</option>`;
	titleContainer.appendChild(titleEl);
	titleContainer.appendChild(select);
	containerEl.appendChild(titleContainer);
	const plotContainer = document.createElement('div');
	containerEl.appendChild(plotContainer);

	function renderDuration(unitCode) {
		plotContainer.innerHTML = '';
		const { width } = containerSize(containerEl);
		const unit = Object.values(TIME_UNITS).find(u => u.code === unitCode) || TIME_UNITS.MINUTES;
		const transformedData = data.map(d => ({
			[labelKey]: d[labelKey],
			fullLabel: d.fullLabel || d[labelKey],
			duration: d[valueKey] / unit.divisor
		}));
		setContainerHeight(containerEl, heightConfig.containerHeight);
		const plot = Plot.plot({
			title: null,
			x: { label: unit.label },
			y: { label: heightConfig.yLabel, domain: data.map(d => d[labelKey]) },
			marks: [Plot.barX(transformedData, {
				y: labelKey,
				x: 'duration',
				fill: fillColor,
				title: d => `${d.fullLabel}: ${d.duration.toFixed(2)} ${unit.label}`
			})],
			width,
			height: heightConfig.plotHeight,
			marginLeft: heightConfig.marginLeft
		});
		plotContainer.appendChild(plot);
	}

	renderDuration(TIME_UNITS.MINUTES.code);
	select.addEventListener('change', () => renderDuration(select.value));
}

/**
 * Creates a cycles chart displaying average cycles per benchmark or sample.
 * @param {HTMLElement} containerEl - Container element.
 * @param {string} title - Chart title.
 * @param {Array<Object>} data - Chart data.
 * @param {string} labelKey - Key for label data.
 * @param {string} valueKey - Key for value data.
 * @param {string} fillColor - Bar fill color.
 * @param {Object} heightConfig - Height configuration object.
 */
function createCyclesChart(containerEl, title, data, labelKey, valueKey, fillColor, heightConfig) {
	containerEl.innerHTML = '';
	appendTitle(containerEl, title);
	const { width } = containerSize(containerEl);
	setContainerHeight(containerEl, heightConfig.containerHeight);
	const plot = Plot.plot({
		title: null,
		x: { label: 'Average Cycles' },
		y: { label: heightConfig.yLabel, domain: data.map(d => d[labelKey]) },
		marks: [Plot.barX(data, {
			y: labelKey,
			x: valueKey,
			fill: fillColor,
			title: d => `${d.fullLabel || d[labelKey]}: ${d[valueKey]}`
		})],
		width,
		height: heightConfig.plotHeight,
		marginLeft: heightConfig.marginLeft
	});
	containerEl.appendChild(plot);
}

/**
 * Initializes all charts and visualizations on the page.
 */
function initializeCharts() {
	const BarY = getBarY();
	if (!BarY) return;

	addProjectBuildRateColumn();

	const idxNew = getProjectSummaryColumnIndex(COLUMN_NAMES.NEW_COVERED_LINES);
	const idxExisting = getProjectSummaryColumnIndex(COLUMN_NAMES.EXISTING_COVERED_LINES);
	const idxTotalLines = getProjectSummaryColumnIndex(COLUMN_NAMES.TOTAL_PROJECT_LINES);

	const projectData = Array.from(document.querySelectorAll('#project-summary-table tbody tr.project-data-row')).map(row => {
		const cells = row.querySelectorAll('td');
		if (cells.length > Math.max(idxNew, idxExisting, idxTotalLines) && idxNew !== -1 && idxExisting !== -1 && idxTotalLines !== -1) {
			const projectName = cells[1].dataset.sortValue;
			return {
				project: projectName,
				projectLabel: truncateLabel(projectName),
				fullLabel: projectName,
				new_lines: parseInt(cells[idxNew].dataset.sortValue) || 0,
				existing_lines: parseInt(cells[idxExisting].dataset.sortValue) || 0,
				total_lines: parseInt(cells[idxTotalLines].dataset.sortValue) || 0
			};
		}
		return null;
	}).filter(Boolean);

	const coverageEl = document.getElementById(ELEMENT_IDS.COVERAGE_CHART);
	if (projectData.length > 0 && coverageEl) {
		try {
			coverageEl.innerHTML = '';
			appendTitle(coverageEl, 'New vs Existing Code Coverage by Project');

			const controlsDiv = document.createElement('div');
			controlsDiv.style.display = 'flex';
			controlsDiv.style.alignItems = 'center';
			controlsDiv.style.gap = '16px';
			controlsDiv.style.marginBottom = '8px';

			const legendDiv = document.createElement('div');
			legendDiv.style.display = 'flex';
			legendDiv.style.gap = '16px';
			legendDiv.style.alignItems = 'center';
			legendDiv.style.fontSize = '14px';
			legendDiv.innerHTML = `<span style="display:inline-flex;align-items:center;gap:6px"><span style="display:inline-block;width:12px;height:12px;background:${COLORS.EXISTING_COVERAGE}"></span><span>Existing Coverage</span></span><span style="display:inline-flex;align-items:center;gap:6px"><span style="display:inline-block;width:12px;height:12px;background:${COLORS.NEW_COVERAGE}"></span><span>New Coverage</span></span>`;

			const normalizeWrapper = document.createElement('label');
			normalizeWrapper.style.display = 'inline-flex';
			normalizeWrapper.style.alignItems = 'center';
			normalizeWrapper.style.gap = '8px';
			const normalizeInput = document.createElement('input');
			normalizeInput.type = 'checkbox';
			normalizeInput.id = ELEMENT_IDS.COVERAGE_NORMALIZED;
			const normalizeText = document.createElement('span');
			normalizeText.textContent = 'Normalized (%)';
			normalizeWrapper.appendChild(normalizeInput);
			normalizeWrapper.appendChild(normalizeText);

			controlsDiv.appendChild(legendDiv);
			controlsDiv.appendChild(normalizeWrapper);
			coverageEl.appendChild(controlsDiv);

			const plotContainer = document.createElement('div');
			coverageEl.appendChild(plotContainer);

			function renderCoveragePlot(normalized) {
				plotContainer.innerHTML = '';
				const { width, height } = containerSize(coverageEl);
				const xLabel = normalized ? 'Percent of Covered Lines' : 'Lines of Code';
				const xOptions = normalized ? { label: xLabel, domain: [0, 100] } : { label: xLabel };
				const yDomain = projectData.map(d => d.projectLabel);
				const longest = yDomain.reduce((m, l) => Math.max(m, (l || '').length), 0);
				const marginLeft = Math.min(MARGIN_LEFT_MAX, Math.max(MARGIN_LEFT_MIN, Math.round(longest * MARGIN_LEFT_MULTIPLIER + MARGIN_LEFT_BASE)));
				const normalizedData = projectData.filter(d => (d.existing_lines + d.new_lines) > 0);
				const marks = normalized ? [
					Plot.rectX(normalizedData, { y: 'projectLabel', x1: 0, x2: d => {
						const covered = (d.existing_lines + d.new_lines) || 0;
						return covered > 0 ? (d.existing_lines / covered) * 100 : 0;
					}, fill: COLORS.EXISTING_COVERAGE, title: d => `${d.project}: Existing Coverage (share of covered)` }),
					Plot.rectX(normalizedData, { y: 'projectLabel', x1: d => {
						const covered = (d.existing_lines + d.new_lines) || 0;
						return covered > 0 ? (d.existing_lines / covered) * 100 : 0;
					}, x2: 100, fill: COLORS.NEW_COVERAGE, title: d => `${d.project}: New Coverage (share of covered)` })
				] : [
					Plot.rectX(projectData, { y: 'projectLabel', x1: 0, x2: 'existing_lines', fill: COLORS.EXISTING_COVERAGE, title: d => `${d.project}: Existing Coverage` }),
					Plot.rectX(projectData, { y: 'projectLabel', x1: 'existing_lines', x2: d => d.existing_lines + d.new_lines, fill: COLORS.NEW_COVERAGE, title: d => `${d.project}: New Coverage` })
				];

				const plotHeight = Math.min(500, Math.max(260, projectData.length * 30 + 80));
				setContainerHeight(coverageEl, plotHeight + 100);
				const plot = Plot.plot({
					title: null,
					x: xOptions,
					y: { label: 'Project', domain: yDomain },
					marks,
					width: Math.max(800, width),
					height: plotHeight,
					marginLeft
				});
				setContainerHeight(coverageEl, plotHeight + 120);
				plotContainer.appendChild(plot);
			}

			renderCoveragePlot(false);
			normalizeInput.addEventListener('change', () => {
				renderCoveragePlot(!!normalizeInput.checked);
			});
		} catch (error) {
			coverageEl.innerHTML = '<p class="text-red-500">' + error.message + '</p>';
		}
	}

	const unified = readUnifiedData();
	if (unified) {
		const crashReasons = {};
		for (const projectName in unified) {
			const project = unified[projectName];
			if (project.benchmarks) {
				for (const benchId in project.benchmarks) {
					const bench = project.benchmarks[benchId];
					if (bench.samples) {
						bench.samples.forEach(s => {
							const bugType = extractBugType((s.crash_symptom || '').trim());
							if (bugType) {
								crashReasons[bugType] = (crashReasons[bugType] || 0) + (s.crashes ? 1 : 0);
							}
						});
					}
				}
			}
		}
		const crEl = document.getElementById(ELEMENT_IDS.CRASH_REASONS_CHART);
		const crashReasonData = Object.entries(crashReasons).map(([reason, count]) => ({ reason, count })).sort((a,b) => b.count - a.count);
		if (crashReasonData.length > 0 && crEl) {
			try {
				crEl.innerHTML = '';
				appendTitle(crEl, 'Crash Reasons');
				if (!renderCrashReasonsPie(crEl, crashReasonData, unified)) {
					const { width, height } = containerSize(crEl);
					const crPlot = Plot.plot({
						title: null,
						x: { label: 'Reason', domain: crashReasonData.map(d => d.reason) },
						y: { label: 'Count' },
						marks: [
							BarY(crashReasonData, { x: 'reason', y: 'count', fill: COLORS.CRASH_REASON })
						],
						width,
						height: Math.max(240, height - 28)
					});
					setContainerHeight(crEl, Math.max(240, height - 28) + 16);
					crEl.appendChild(crPlot);
				}
			} catch (error) {
				crEl.innerHTML = '<p class="text-red-500">' + error.message + '</p>';
			}
		}

		try {
			const projData = Object.entries(unified).map(([projectName, pdata]) => ({
				project: projectName,
				projectLabel: truncateLabel(projectName),
				fullLabel: projectName,
				cycles: Number(pdata.average_cycles_per_benchmark || 0),
				durationSec: Number(pdata.average_trial_duration_sec || 0)
			}));
			const projCyclesEl = document.getElementById(ELEMENT_IDS.CYCLES_PROJECTS_CHART);
			const projDurEl = document.getElementById(ELEMENT_IDS.DURATION_PROJECTS_CHART);
			if (projData.length && projCyclesEl && projDurEl) {
				const sharedProjectHeight = Math.min(400, Math.max(240, projData.length * 30 + 80));
				const sharedProjectContainerHeight = sharedProjectHeight + 60;
				const projectHeightConfig = {
					plotHeight: sharedProjectHeight,
					containerHeight: sharedProjectContainerHeight,
					marginLeft: 120,
					yLabel: 'Project'
				};

				createCyclesChart(projCyclesEl, 'Average Cycles per Benchmark (by Project)',
					projData, 'projectLabel', 'cycles', COLORS.CYCLES_PROJECT, projectHeightConfig);

				createDurationChart(projDurEl, 'Average Trial Duration (by Project)',
					projData, 'projectLabel', 'durationSec', COLORS.DURATION_PROJECT, projectHeightConfig);
			}

			const benchData = [];
			for (const projectName in unified) {
				const pdata = unified[projectName];
				if (!pdata || !pdata.benchmarks) continue;
				for (const benchId in pdata.benchmarks) {
					const b = pdata.benchmarks[benchId];
					const prettyName = typeof prettifyBenchmarkName === 'function' ? prettifyBenchmarkName(benchId) : benchId;
					benchData.push({
						project: projectName,
						benchmark: benchId,
						benchmarkLabel: truncateLabel(prettyName),
						fullLabel: benchId,
						cycles: Number(b.avg_cycles_per_sample || 0),
						durationSec: Number(b.avg_trial_duration_sec || 0)
					});
				}
			}
			const benchCyclesEl = document.getElementById(ELEMENT_IDS.CYCLES_BENCHMARKS_CHART);
			const benchDurEl = document.getElementById(ELEMENT_IDS.DURATION_BENCHMARKS_CHART);
			if (benchData.length && benchCyclesEl && benchDurEl) {
				const sharedBenchHeight = Math.min(500, Math.max(300, benchData.length * 18 + 80));
				const sharedBenchContainerHeight = sharedBenchHeight + 60;
				const benchHeightConfig = {
					plotHeight: sharedBenchHeight,
					containerHeight: sharedBenchContainerHeight,
					marginLeft: 140,
					yLabel: 'Benchmark'
				};

				createCyclesChart(benchCyclesEl, 'Average Cycles per Sample (by Benchmark)',
					benchData, 'benchmarkLabel', 'cycles', COLORS.CYCLES_BENCH, benchHeightConfig);

				createDurationChart(benchDurEl, 'Average Trial Duration (by Benchmark)',
					benchData, 'benchmarkLabel', 'durationSec', COLORS.DURATION_BENCH, benchHeightConfig);
			}
		} catch (error) {
			console.error('Failed to render benchmark charts:', error);
		}
	}
}

/**
 * Toggles visibility of elements matching a selector.
 * @param {string} selector - CSS selector for elements to toggle.
 * @param {boolean} show - Whether to show (true) or hide (false) elements.
 */
function toggleElements(selector, show) {
	document.querySelectorAll(selector).forEach(el => {
		el.classList.toggle('hidden', !show);
	});
}

/**
 * Compares two table cells for sorting.
 * @param {HTMLTableCellElement} cellA - First cell to compare.
 * @param {HTMLTableCellElement} cellB - Second cell to compare.
 * @param {boolean} sortNumber - Whether to compare as numbers.
 * @param {boolean} sortAsc - Whether to sort in ascending order.
 * @returns {number} Comparison result (-1, 0, or 1).
 */
function compareTableCells(cellA, cellB, sortNumber, sortAsc) {
	if (!cellA || !cellB) return 0;

	const valueA_str = cellA.dataset.sortValue;
	const valueB_str = cellB.dataset.sortValue;
	let comparison = 0;

	if (sortNumber) {
		const numA = parseFloat(valueA_str);
		const numB = parseFloat(valueB_str);

		if (isNaN(numA) && isNaN(numB)) {
			comparison = 0;
		} else if (isNaN(numA)) {
			comparison = 1;
		} else if (isNaN(numB)) {
			comparison = -1;
		} else {
			comparison = numA - numB;
		}
	} else {
		const strA = (valueA_str === undefined || valueA_str === null) ? "" : String(valueA_str);
		const strB = (valueB_str === undefined || valueB_str === null) ? "" : String(valueB_str);
		comparison = strA.localeCompare(strB);
	}
	return sortAsc ? comparison : -comparison;
}

/**
 * Sets up table sorting functionality for all sortable tables.
 */
function setupTableSorting() {
	const tables = Array.from(document.querySelectorAll('table.sortable-table'));
	tables.forEach(table_element => {
		const headers = Array.from(table_element.querySelectorAll(':scope > thead > tr > th'));
		headers.forEach((th) => {
			if (th.innerText.trim() === '' && Array.from(th.parentElement.children).indexOf(th) === 0) {
				return;
			}

			th.addEventListener('click', () => {
				const currentTableHeaders = Array.from(table_element.querySelectorAll(':scope > thead > tr > th'));
				const colindex = currentTableHeaders.indexOf(th);

				const sortAsc = th.dataset.sorted !== "asc";
				const sortNumber = th.hasAttribute('data-sort-number');

				currentTableHeaders.forEach(innerTH => delete innerTH.dataset.sorted);
				th.dataset.sorted = sortAsc ? "asc" : "desc";

				const tbody = table_element.querySelector(':scope > tbody');
				if (!tbody) return;

				let allRowsInBody = Array.from(tbody.children);
				const sortableUnits = [];
				const nonsortableRows = [];

				allRowsInBody = allRowsInBody.filter(row => {
					if (row.hasAttribute('data-nosort') || row.classList.contains('font-bold')) {
						nonsortableRows.push(row);
						return false;
					}
					return true;
				});

				let i = 0;
				while (i < allRowsInBody.length) {
					const currentRow = allRowsInBody[i];
					const nextRow = allRowsInBody[i + 1];

					const hasCompanion = nextRow && (
						(currentRow.classList.contains('project-data-row') && nextRow.classList.contains('project-benchmarks-container-row')) ||
						(currentRow.querySelector('button') && nextRow.querySelector('[x-ref]')) ||
						(!currentRow.classList.contains('project-data-row') && !currentRow.classList.contains('project-benchmarks-container-row') && nextRow.querySelector('td[colspan]'))
					);

					if (hasCompanion) {
						sortableUnits.push({
							representativeRow: currentRow,
							actualRows: [currentRow, nextRow]
						});
						i += 2;
					} else {
						sortableUnits.push({
							representativeRow: currentRow,
							actualRows: [currentRow]
						});
						i += 1;
					}
				}

				sortableUnits.sort((unitA, unitB) => {
					const cellA = unitA.representativeRow.children[colindex];
					const cellB = unitB.representativeRow.children[colindex];
					return compareTableCells(cellA, cellB, sortNumber, sortAsc);
				});

				tbody.innerHTML = '';
				sortableUnits.forEach(unit => {
					unit.actualRows.forEach(row => tbody.appendChild(row));
				});
				nonsortableRows.forEach(row => tbody.appendChild(row));

				let visualIndex = 1;
				Array.from(tbody.children).forEach(r => {
					if (nonsortableRows.includes(r)) {
						return;
					}
					const firstCell = r.children[0];
					if (firstCell && firstCell.classList.contains('table-index') && !firstCell.querySelector('button')) {
						firstCell.innerText = visualIndex++;
					}
				});
			});
		});
	});
}

document.addEventListener('DOMContentLoaded', function() {
	const plotCheckInterval = setInterval(() => {
		if (typeof Plot !== 'undefined') {
			clearInterval(plotCheckInterval);
			initializeCharts();
		}
	}, 100);

	const projectSummaryExpandAllButton = document.getElementById(ELEMENT_IDS.PROJECT_SUMMARY_EXPAND);
	if (projectSummaryExpandAllButton) {
		projectSummaryExpandAllButton.addEventListener('click', () => toggleElements(SELECTORS.BENCHMARKS, true));
	}

	const projectSummaryCollapseAllButton = document.getElementById(ELEMENT_IDS.PROJECT_SUMMARY_COLLAPSE);
	if (projectSummaryCollapseAllButton) {
		projectSummaryCollapseAllButton.addEventListener('click', () => toggleElements(SELECTORS.BENCHMARKS, false));
	}

	const crashesExpandAllButton = document.getElementById(ELEMENT_IDS.CRASHES_EXPAND);
	if (crashesExpandAllButton) {
		crashesExpandAllButton.addEventListener('click', () => {
			toggleElements(SELECTORS.PROJECT_CRASHES, true);
			toggleElements(SELECTORS.SAMPLE_CRASHES, true);
		});
	}

	const crashesCollapseAllButton = document.getElementById(ELEMENT_IDS.CRASHES_COLLAPSE);
	if (crashesCollapseAllButton) {
		crashesCollapseAllButton.addEventListener('click', () => {
			toggleElements(SELECTORS.PROJECT_CRASHES, false);
			toggleElements(SELECTORS.SAMPLE_CRASHES, false);
		});
	}

	document.querySelectorAll('[id^="project-expand-all-"]').forEach(button => {
		button.addEventListener('click', () => {
			const projectIndex = button.id.split('-').pop();
			toggleElements(`[x-ref^="samples_"][x-ref$="_${projectIndex}"]`, true);
		});
	});

	document.querySelectorAll('[id^="project-collapse-all-"]').forEach(button => {
		button.addEventListener('click', () => {
			const projectIndex = button.id.split('-').pop();
			toggleElements(`[x-ref^="samples_"][x-ref$="_${projectIndex}"]`, false);
		});
	});

	setupTableSorting();
});
