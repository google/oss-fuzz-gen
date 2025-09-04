document.addEventListener('DOMContentLoaded', function() {
	function waitForPlot() {
		if (typeof Plot !== 'undefined') {
			setTimeout(initializeCharts, 100);
		} else {
			setTimeout(waitForPlot, 100);
		}
	}

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

	function readUnifiedData() {
		const el = document.getElementById('unified-data');
		if (!el) return null;
		try { return JSON.parse(el.textContent); } catch (_) { return null; }
	}

	function containerSize(el, fallbackW = 800, fallbackH = 300) {
		if (!el) return { width: fallbackW, height: fallbackH };
		const rect = el.getBoundingClientRect();
		const width = Math.max(300, Math.floor(rect.width - 20));
		const height = Math.max(220, Math.floor(rect.height - 20));
		return { width, height };
	}

	function setContainerHeight(el, height) {
		if (el) {
			el.style.height = `${height}px`;
		}
	}

	function appendTitle(el, text) {
		const title = document.createElement('div');
		title.textContent = text;
		title.style.fontWeight = '600';
		title.style.marginBottom = '8px';
		el.appendChild(title);
	}

	function appendControls(el) {
		const wrap = document.createElement('div');
		wrap.style.display = 'flex';
		wrap.style.alignItems = 'center';
		wrap.style.gap = '12px';
		wrap.style.marginBottom = '8px';
		el.appendChild(wrap);
		return wrap;
	}

	function truncateLabel(str, max = 20) {
		if (!str) return '';
		if (str.length <= max) return str;
		return str.slice(0, max - 1) + '…';
	}

	function extractBugType(symptom) {
		if (!symptom || typeof symptom !== 'string') return '';
		const betweenMatch = symptom.match(/AddressSanitizer:\s*(.+?)\s+on\b/i);
		if (betweenMatch) return betweenMatch[1].trim().toLowerCase();
		const fallback = symptom.match(/ERROR:\s*AddressSanitizer:\s*([A-Za-z0-9_-]+)/i);
		return fallback ? fallback[1].toLowerCase() : '';
	}

	function addProjectBuildRateColumn() {
		const table = document.getElementById('project-summary-table');
		if (!table) return;
		const theadRow = table.querySelector('thead tr');
		if (!theadRow) return;
		const ths = Array.from(theadRow.querySelectorAll('th'));
		let insertIdx = -1;
		for (let i = 0; i < ths.length; i++) {
			const txt = (ths[i].textContent || '').trim().toLowerCase();
			if (txt.includes('successful benchmarks')) { insertIdx = i + 1; break; }
		}
		if (insertIdx === -1) return;

		const newTh = document.createElement('th');
		newTh.setAttribute('data-sort-number', '');
		newTh.textContent = 'Build rate';
		const refTh = ths[insertIdx] || null;
		if (refTh) theadRow.insertBefore(newTh, refTh); else theadRow.appendChild(newTh);

		const rows = Array.from(table.querySelectorAll('tbody tr'));
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

	function getProjectSummaryColumnIndex(substr) {
		const table = document.getElementById('project-summary-table');
		if (!table) return -1;
		const ths = Array.from(table.querySelectorAll('thead th'));
		for (let i = 0; i < ths.length; i++) {
			const txt = (ths[i].textContent || '').trim().toLowerCase();
			if (txt.includes(substr.toLowerCase())) return i;
		}
		return -1;
	}

	function renderCrashReasonsPie(el, data) {
		if (typeof d3 === 'undefined') return false;
		try {
			const children = Array.from(el.children);
			for (let i = 1; i < children.length; i++) {
				el.removeChild(children[i]);
			}
		} catch (_) {}
		const { width, height } = containerSize(el);
		const svgHeight = Math.max(240, height - 28);
		const legend = d3.select(el).append('div')
			.style('display','flex')
			.style('flexWrap','wrap')
			.style('gap','10px')
			.style('justifyContent','center')
			.style('marginBottom','8px');
		const scheme = (d3.schemeTableau10 || d3.schemeCategory10 || []);
		const color = scheme.length ? d3.scaleOrdinal(scheme) : d3.scaleOrdinal().range(['#3b82f6','#22c55e','#ef4444','#f59e0b','#8b5cf6','#06b6d4','#84cc16','#e11d48','#64748b','#a855f7']);
		color.domain(data.map(d=>d.reason));
		data.forEach(d => {
			const item = legend.append('div').style('display','flex').style('alignItems','center').style('gap','6px');
			item.append('span').style('display','inline-block').style('width','12px').style('height','12px').style('background', color(d.reason));
			item.append('span').text(`${d.reason}: ${d.count}`);
		});
		const values = data.map(d => d.count || 0);
		const sum = values.reduce((a,b)=>a+b,0);
		if (sum <= 0) { el.appendChild(document.createTextNode('No crash reasons')); return true; }
		const radius = Math.min(width, svgHeight) / 2 - 8;
		const svg = d3.select(el).append('svg').attr('width', width).attr('height', svgHeight)
			.append('g').attr('transform', `translate(${width/2},${svgHeight/2})`);
		const pie = d3.pie().sort(null).value(d => d.count)(data);
		const arc = d3.arc().outerRadius(radius).innerRadius(0);
		svg.selectAll('path').data(pie).enter().append('path')
			.attr('d', arc)
			.attr('fill', d => color(d.data.reason))
			.append('title').text(d => `${d.data.reason}: ${d.data.count}`);
		return true;
	}

	function initializeCharts() {
		const BarY = getBarY();
		if (!BarY) return;

		// duration helpers (shared)
		function durationScaled(valSec, unit) { return unit === 'm' ? valSec / 60 : (unit === 'h' ? valSec / 3600 : valSec); }
		function unitLabel(unit) { return unit === 'm' ? 'Minutes' : (unit === 'h' ? 'Hours' : 'Seconds'); }

		addProjectBuildRateColumn();

		const idxNew = getProjectSummaryColumnIndex('oss-fuzz-gen new covered lines');
		const idxExisting = getProjectSummaryColumnIndex('existing covered lines');

		const projectData = Array.from(document.querySelectorAll('#project-summary-table tbody tr.project-data-row')).map(row => {
			const cells = row.querySelectorAll('td');
			if (cells.length > Math.max(idxNew, idxExisting) && idxNew !== -1 && idxExisting !== -1) {
				return {
					project: cells[1].dataset.sortValue,
					projectLabel: truncateLabel(cells[1].dataset.sortValue),
					new_lines: parseInt(cells[idxNew].dataset.sortValue) || 0,
					existing_lines: parseInt(cells[idxExisting].dataset.sortValue) || 0
				};
			}
			return null;
		}).filter(Boolean);

		const coverageEl = document.getElementById('coverage-chart');
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
				legendDiv.innerHTML = '<span style="display:inline-flex;align-items:center;gap:6px"><span style="display:inline-block;width:12px;height:12px;background:#94a3b8"></span>Existing Coverage</span><span style="display:inline-flex;align-items:center;gap:6px"><span style="display:inline-block;width:12px;height:12px;background+#3b82f6"></span>New Coverage</span>'.replace('background+','#3b82f6').replace('background','background:');

				const normalizeWrapper = document.createElement('label');
				normalizeWrapper.style.display = 'inline-flex';
				normalizeWrapper.style.alignItems = 'center';
				normalizeWrapper.style.gap = '8px';
				const normalizeInput = document.createElement('input');
				normalizeInput.type = 'checkbox';
				normalizeInput.id = 'coverage-normalized';
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
					const xLabel = normalized ? 'Percent of Project Lines' : 'Lines of Code';
					const xOptions = normalized ? { label: xLabel, domain: [0, 100] } : { label: xLabel };
					const marks = normalized ? [
						Plot.rectX(projectData, { y: 'projectLabel', x1: 0, x2: d => {
							const total = (d.existing_lines + d.new_lines) || 1;
							return (d.existing_lines / total) * 100;
						}, fill: '#94a3b8', title: d => `${d.project}: Existing Coverage (%)` }),
						Plot.rectX(projectData, { y: 'projectLabel', x1: d => {
							const total = (d.existing_lines + d.new_lines) || 1;
							return (d.existing_lines / total) * 100;
						}, x2: 100, fill: '#3b82f6', title: d => `${d.project}: New Coverage (%)` })
					] : [
						Plot.rectX(projectData, { y: 'projectLabel', x1: 0, x2: 'existing_lines', fill: '#94a3b8', title: d => `${d.project}: Existing Coverage` }),
						Plot.rectX(projectData, { y: 'projectLabel', x1: 'existing_lines', x2: d => d.existing_lines + d.new_lines, fill: '#3b82f6', title: d => `${d.project}: New Coverage` })
					];

					const plotHeight = Math.min(500, Math.max(260, projectData.length * 30 + 80));
					setContainerHeight(coverageEl, plotHeight + 100);
					const plot = Plot.plot({
						title: null,
						x: xOptions,
						y: { label: 'Project', domain: projectData.map(d => d.projectLabel) },
						marks,
						width: Math.max(800, width),
						height: plotHeight
					});
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
								const reason = bugType || 'N/A';
								crashReasons[reason] = (crashReasons[reason] || 0) + (s.crashes ? 1 : 0);
							});
						}
					}
				}
			}
			const crEl = document.getElementById('crash-reasons-chart');
			const crashReasonData = Object.entries(crashReasons).map(([reason, count]) => ({ reason, count })).sort((a,b) => b.count - a.count);
			if (crashReasonData.length > 0 && crEl) {
				try {
					crEl.innerHTML = '';
					appendTitle(crEl, 'Crash Reasons');
					if (!renderCrashReasonsPie(crEl, crashReasonData)) {
						const { width, height } = containerSize(crEl);
						const crPlot = Plot.plot({
							title: null,
							x: { label: 'Reason', domain: crashReasonData.map(d => d.reason) },
							y: { label: 'Count' },
							marks: [
								BarY(crashReasonData, { x: 'reason', y: 'count', fill: '#f59e0b' })
							],
							width,
							height: Math.max(240, height - 28)
						});
						crEl.appendChild(crPlot);
					}
				} catch (error) {
					crEl.innerHTML = '<p class="text-red-500">' + error.message + '</p>';
				}
			}

			const cyclesProject = '#3b82f6'; // blue-500
			const durationProject = '#9ca3af'; // gray-400
			const cyclesBench = '#1d4ed8'; // blue-700
			const durationBench = '#6b7280'; // gray-500

			try {
				const projData = Object.entries(unified).map(([projectName, pdata]) => ({
					project: projectName,
					projectLabel: truncateLabel(projectName),
					cycles: Number(pdata.average_cycles_per_benchmark || 0),
					durationSec: Number(pdata.average_trial_duration_sec || 0)
				}));
				const projCyclesEl = document.getElementById('cycles-projects-chart');
				const projDurEl = document.getElementById('duration-projects-chart');
				if (projData.length && projCyclesEl && projDurEl) {
					projCyclesEl.innerHTML = '';
					appendTitle(projCyclesEl, 'Avg Cycles per Benchmark (by Project)');
					let { width, height } = containerSize(projCyclesEl);
					let plot1 = Plot.plot({
						title: null,
						x: { label: 'Avg Cycles' },
						y: { label: 'Project', domain: projData.map(d=>d.projectLabel) },
						marks: [Plot.barX(projData, { y: 'projectLabel', x: 'cycles', fill: cyclesProject, title: d => `${d.project}: ${d.cycles}` })],
						width,
						height: Math.max(240, height - 28)
					});
					projCyclesEl.appendChild(plot1);

					projDurEl.innerHTML = '';
					appendTitle(projDurEl, 'Avg Trial Duration (by Project)');
					const controls = appendControls(projDurEl);
					const select = document.createElement('select');
					select.innerHTML = '<option value="s">Seconds</option><option value="m" selected>Minutes</option><option value="h">Hours</option>';
					controls.appendChild(select);
					const plotContainer = document.createElement('div');
					projDurEl.appendChild(plotContainer);

					function renderProjDuration(unit) {
						plotContainer.innerHTML = '';
						({ width, height } = containerSize(projDurEl));
						const data = projData.map(d => ({ projectLabel: d.projectLabel, project: d.project, duration: durationScaled(d.durationSec, unit) }));
						const plot2 = Plot.plot({
							title: null,
							x: { label: unitLabel(unit) },
							y: { label: 'Project', domain: data.map(d=>d.projectLabel) },
							marks: [Plot.barX(data, { y: 'projectLabel', x: 'duration', fill: durationProject, title: d => `${d.project}: ${d.duration.toFixed(2)} ${unitLabel(unit)}` })],
							width,
							height: Math.max(240, height - 28)
						});
						plotContainer.appendChild(plot2);
					}

					renderProjDuration('m');
					select.addEventListener('change', () => renderProjDuration(select.value));
				}

				const benchData = [];
				for (const projectName in unified) {
					const pdata = unified[projectName];
					if (!pdata || !pdata.benchmarks) continue;
					for (const benchId in pdata.benchmarks) {
						const b = pdata.benchmarks[benchId];
						const prettyName = typeof prettifyBenchmarkName === 'function' ? prettifyBenchmarkName(benchId) : benchId;
						benchData.push({ project: projectName, benchmark: benchId,
							benchmarkLabel: truncateLabel(prettyName),
							cycles: Number(b.avg_cycles_per_sample || 0),
							durationSec: Number(b.avg_trial_duration_sec || 0) });
					}
				}
				const benchCyclesEl = document.getElementById('cycles-benchmarks-chart');
				const benchDurEl = document.getElementById('duration-benchmarks-chart');
				if (benchData.length && benchCyclesEl && benchDurEl) {
					benchCyclesEl.innerHTML = '';
					appendTitle(benchCyclesEl, 'Avg Cycles per Sample (by Benchmark)');
					let { width, height } = containerSize(benchCyclesEl);
					const plotHeight = Math.min(600, Math.max(300, benchData.length * 20 + 60));
					setContainerHeight(benchCyclesEl, plotHeight + 40);
					let plot3 = Plot.plot({
						title: null,
						x: { label: 'Avg Cycles' },
						y: { label: 'Benchmark', domain: benchData.map(d=>d.benchmarkLabel) },
						marks: [Plot.barX(benchData, { y: 'benchmarkLabel', x: 'cycles', fill: cyclesBench, title: d => `${d.benchmark}: ${d.cycles}` })],
						marginLeft: 120,
						width,
						height: plotHeight
					});
					benchCyclesEl.appendChild(plot3);

					benchDurEl.innerHTML = '';
					appendTitle(benchDurEl, 'Avg Trial Duration (by Benchmark)');
					const controlsB = appendControls(benchDurEl);
					const selectB = document.createElement('select');
					selectB.innerHTML = '<option value="s">Seconds</option><option value="m" selected>Minutes</option><option value="h">Hours</option>';
					controlsB.appendChild(selectB);
					const plotContainerB = document.createElement('div');
					benchDurEl.appendChild(plotContainerB);

					function renderBenchDuration(unit) {
						plotContainerB.innerHTML = '';
						({ width, height } = containerSize(benchDurEl));
						const data = benchData.map(d => ({ benchmarkLabel: d.benchmarkLabel, benchmark: d.benchmark, duration: durationScaled(d.durationSec, unit) }));
						const plotHeight = Math.min(600, Math.max(300, benchData.length * 20 + 60));
						setContainerHeight(benchDurEl, plotHeight + 80);
						const plot4 = Plot.plot({
							title: null,
							x: { label: unitLabel(unit) },
							y: { label: 'Benchmark', domain: data.map(d=>d.benchmarkLabel) },
							marks: [Plot.barX(data, { y: 'benchmarkLabel', x: 'duration', fill: durationBench, title: d => `${d.benchmark}: ${d.duration.toFixed(2)} ${unitLabel(unit)}` })],
							marginLeft: 120,
							width,
							height: plotHeight
						});
						plotContainerB.appendChild(plot4);
					}

					renderBenchDuration('m');
					selectB.addEventListener('change', () => renderBenchDuration(selectB.value));
				}
			} catch (_) {}
		}
	}

	waitForPlot();

	const projectSummaryExpandAllButton = document.getElementById('project-summary-expand-all');
	if (projectSummaryExpandAllButton) {
		projectSummaryExpandAllButton.addEventListener('click', () => {
			document.querySelectorAll('[x-ref^="benchmarks_"]').forEach(el => {
				el.classList.remove('hidden');
			});
		});
	}

	const projectSummaryCollapseAllButton = document.getElementById('project-summary-collapse-all');
	if (projectSummaryCollapseAllButton) {
		projectSummaryCollapseAllButton.addEventListener('click', () => {
			document.querySelectorAll('[x-ref^="benchmarks_"]').forEach(el => {
				el.classList.add('hidden');
			});
		});
	}

	const crashesExpandAllButton = document.getElementById('crashes-expand-all');
	if (crashesExpandAllButton) {
		crashesExpandAllButton.addEventListener('click', () => {
			document.querySelectorAll('[x-ref^="project_"]').forEach(el => {
				el.classList.remove('hidden');
			});
			document.querySelectorAll('[x-ref^="samples_"]').forEach(el => {
				el.classList.remove('hidden');
			});
		});
	}

	const crashesCollapseAllButton = document.getElementById('crashes-collapse-all');
	if (crashesCollapseAllButton) {
		crashesCollapseAllButton.addEventListener('click', () => {
			document.querySelectorAll('[x-ref^="project_"]').forEach(el => {
				el.classList.add('hidden');
			});
			document.querySelectorAll('[x-ref^="samples_"]').forEach(el => {
				el.classList.add('hidden');
			});
		});
	}

	document.querySelectorAll('[id^="project-expand-all-"]').forEach(button => {
		button.addEventListener('click', () => {
			const projectIndex = button.id.split('-').pop();
			document.querySelectorAll(`[x-ref^="samples_"][x-ref$="_${projectIndex}"]`).forEach(el => {
				el.classList.remove('hidden');
			});
		});
	});

	document.querySelectorAll('[id^="project-collapse-all-"]').forEach(button => {
		button.addEventListener('click', () => {
			const projectIndex = button.id.split('-').pop();
			document.querySelectorAll(`[x-ref^="samples_"][x-ref$="_${projectIndex}"]`).forEach(el => {
				el.classList.add('hidden');
			});
		});
	});

	function compareTableCells(cellA, cellB, sortNumber, sortAsc) {
		if (!cellA || !cellB) return 0;

		let valueA_str = cellA.dataset.sortValue;
		let valueB_str = cellB.dataset.sortValue;
		let comparison = 0;

		if (sortNumber) {
			let numA = parseFloat(valueA_str);
			let numB = parseFloat(valueB_str);

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

	const tables = Array.from(document.querySelectorAll('table.sortable-table'));
	tables.forEach(table_element => {
		const headers = Array.from(table_element.querySelectorAll('th'));
		headers.forEach((th, colindex) => {
			if (th.innerText.trim() === '' && colindex === 0) {
				return;
			}

			th.addEventListener('click', () => {
				const sortAsc = th.dataset.sorted !== "asc";
				const sortNumber = th.hasAttribute('data-sort-number');

				const currentTableHeaders = Array.from(table_element.querySelectorAll('th'));
				currentTableHeaders.forEach(innerTH => delete innerTH.dataset.sorted);
				th.dataset.sorted = sortAsc ? "asc" : "desc";

				const tbody = table_element.querySelector('tbody');
				if (!tbody) return;

				let allRowsInBody = Array.from(tbody.children);
				let sortableUnits = [];
				let appendedRows = [];

				if (table_element.id === 'project-summary-table') {
					for (let i = 0; i < allRowsInBody.length; i += 2) {
						if (allRowsInBody[i] && allRowsInBody[i+1] &&
							allRowsInBody[i].classList.contains('project-data-row') &&
							allRowsInBody[i+1].classList.contains('project-benchmarks-container-row')) {
							sortableUnits.push({
								representativeRow: allRowsInBody[i],
								actualRows: [allRowsInBody[i], allRowsInBody[i+1]]
							});
						} else {
							appendedRows.push(...allRowsInBody.slice(i));
							break;
						}
					}
				} else if (table_element.id === 'crashes-table') {
					for (let i = 0; i < allRowsInBody.length; i += 2) {
						if (allRowsInBody[i] && allRowsInBody[i+1]) {
							sortableUnits.push({
								representativeRow: allRowsInBody[i],
								actualRows: [allRowsInBody[i], allRowsInBody[i+1]]
							});
						}
					}
				} else if (table_element.closest('[x-ref^="project_"]')) {
					for (let i = 0; i < allRowsInBody.length; i += 2) {
						if (allRowsInBody[i] && allRowsInBody[i+1]) {
							sortableUnits.push({
								representativeRow: allRowsInBody[i],
								actualRows: [allRowsInBody[i], allRowsInBody[i+1]]
							});
						}
					}
				} else {
					if (table_element.id && table_element.id.startsWith('benchmarks-table-')) {
						const averageRowIndex = allRowsInBody.findIndex(row => row.cells.length > 0 && row.cells[0].innerText.trim() === 'Average');
						if (averageRowIndex !== -1) {
							appendedRows.push(allRowsInBody.splice(averageRowIndex, 1)[0]);
						}
					}
					allRowsInBody.forEach(row => {
						sortableUnits.push({ representativeRow: row, actualRows: [row] });
					});
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
				appendedRows.forEach(row => tbody.appendChild(row));

				let visualIndex = 1;
				Array.from(tbody.children).forEach(r => {
					if (appendedRows.includes(r)) {
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
});
