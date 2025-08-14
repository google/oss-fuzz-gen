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

	function appendTitle(el, text) {
		const title = document.createElement('div');
		title.textContent = text;
		title.style.fontWeight = '600';
		title.style.marginBottom = '8px';
		el.appendChild(title);
	}

	function renderLanguagePie(langData) {
		const el = document.getElementById('language-coverage-chart');
		if (!el || typeof d3 === 'undefined') return;
		el.innerHTML = '';
		appendTitle(el, 'Language Coverage (Experiment new lines)');
		const { width, height } = containerSize(el);
		const reserved = 60;
		const svgHeight = Math.max(220, height - reserved);
		const legend = d3.select(el).append('div').style('display','flex').style('flexWrap','wrap').style('gap','10px').style('justifyContent','center').style('marginBottom','8px');
		const color = (d3.schemeTableau10 || d3.schemeCategory10 || []).length ? d3.scaleOrdinal((d3.schemeTableau10 || d3.schemeCategory10)) : d3.scaleOrdinal().range(['#3b82f6','#22c55e','#ef4444','#f59e0b','#8b5cf6','#06b6d4','#84cc16','#e11d48','#64748b','#a855f7']);
		color.domain(langData.map(d=>d.language));
		langData.forEach(d => {
			const item = legend.append('div').style('display','flex').style('alignItems','center').style('gap','6px');
			item.append('span').style('display','inline-block').style('width','12px').style('height','12px').style('background', color(d.language));
			item.append('span').text(`${d.language}: ${d.experiment_new}`);
		});
		const values = langData.map(d => d.experiment_new || 0);
		const sum = values.reduce((a,b)=>a+b,0);
		if (sum <= 0) { el.innerHTML = '<p class="text-gray-500">No language coverage data</p>'; return; }
		const radius = Math.min(width, svgHeight) / 2 - 8;
		const svg = d3.select(el).append('svg').attr('width', width).attr('height', svgHeight)
			.append('g').attr('transform', `translate(${width/2},${svgHeight/2})`);
		const pie = d3.pie().sort(null).value(d => d.experiment_new)(langData);
		const arc = d3.arc().outerRadius(radius).innerRadius(radius*0.5);
		svg.selectAll('path').data(pie).enter().append('path')
			.attr('d', arc)
			.attr('fill', d => color(d.data.language))
			.append('title').text(d => `${d.data.language}: ${d.data.experiment_new}`);
	}

	function initializeCharts() {
		const BarY = getBarY();
		if (!BarY) return;

		const projectData = Array.from(document.querySelectorAll('#project-summary-table tbody tr.project-data-row')).map(row => {
			const cells = row.querySelectorAll('td');
			if (cells.length >= 9) {
				return {
					project: cells[1].dataset.sortValue,
					new_lines: parseInt(cells[7].dataset.sortValue) || 0,
					existing_lines: parseInt(cells[8].dataset.sortValue) || 0
				};
			}
			return null;
		}).filter(Boolean);

		const coverageEl = document.getElementById('coverage-chart');
		if (projectData.length > 0 && coverageEl) {
			try {
				coverageEl.innerHTML = '';
				appendTitle(coverageEl, 'New vs Existing Code Coverage by Project');
				const legendDiv = document.createElement('div');
				legendDiv.style.display = 'flex';
				legendDiv.style.gap = '16px';
				legendDiv.style.alignItems = 'center';
				legendDiv.style.fontSize = '14px';
				legendDiv.style.marginBottom = '6px';
				legendDiv.innerHTML = '<span style="display:inline-flex;align-items:center;gap:6px"><span style="display:inline-block;width:12px;height:12px;background:#94a3b8"></span>Existing Coverage</span><span style="display:inline-flex;align-items:center;gap:6px"><span style="display:inline-block;width:12px;height:12px;background:#3b82f6"></span>New Coverage</span>';
				coverageEl.appendChild(legendDiv);
				const { width, height } = containerSize(coverageEl);
				const plot = Plot.plot({
					title: null,
					x: { label: 'Project', domain: projectData.map(d => d.project) },
					y: { label: 'Lines of Code' },
					marks: [
						BarY(projectData, { x: 'project', y: 'existing_lines', fill: '#94a3b8', title: 'Existing Coverage' }),
						BarY(projectData, { x: 'project', y: 'new_lines', fill: '#3b82f6', title: 'New Coverage' })
					],
					width,
					height: Math.max(240, height - 56)
				});
				coverageEl.appendChild(plot);
			} catch (error) {
				coverageEl.innerHTML = '<p class="text-red-500">' + error.message + '</p>';
			}
		}

		const langRows = document.querySelectorAll('#language-coverage-gain tbody tr');
		const langData = Array.from(langRows).map(row => {
			const cells = row.querySelectorAll('td');
			if (cells.length >= 6) {
				return {
					language: cells[0].dataset.sortValue,
					ossfuzz_covered: parseInt(cells[2].dataset.sortValue) || 0,
					experiment_new: parseInt(cells[3].dataset.sortValue) || 0
				};
			}
			return null;
		}).filter(Boolean);
		if (langData.length > 0) {
			try { renderLanguagePie(langData); } catch (_) {}
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
								const reason = (s.crash_reason || '').trim() || 'N/A';
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
				} catch (error) {
					crEl.innerHTML = '<p class="text-red-500">' + error.message + '</p>';
				}
			}
		}
	}

	waitForPlot();

	// Project summary table expand/collapse buttons
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

	// Project-level expand/collapse buttons
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
