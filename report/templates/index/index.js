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

        if (projectData.length > 0) {
            try {
                const coveragePlot = Plot.plot({
                    title: "New vs. Existing Code Coverage by Project",
                    x: { label: "Project", domain: projectData.map(d => d.project) },
                    y: { label: "Lines of Code" },
                    marks: [
                        BarY(projectData, { x: "project", y: "existing_lines", fill: "#94a3b8", title: "Existing Coverage" }),
                        BarY(projectData, { x: "project", y: "new_lines", fill: "#3b82f6", title: "New Coverage" })
                    ],
                    width: 800,
                    height: 400
                });
                const el = document.getElementById('coverage-chart');
                if (el) { el.innerHTML = ''; el.appendChild(coveragePlot); }
            } catch (error) {
                const el = document.getElementById('coverage-chart');
                if (el) el.innerHTML = '<p class="text-red-500">' + error.message + '</p>';
            }
        }

        const bugsData = {};
        projectData.forEach(project => { bugsData[project.project] = 0; });
        const bugRows = document.querySelectorAll('#project-summary-table tbody tr.project-data-row');
        bugRows.forEach(row => {
            const cells = row.querySelectorAll('td');
            if (cells.length >= 6) {
                const project = cells[1].dataset.sortValue;
                const bugs = parseInt(cells[5].dataset.sortValue) || 0;
                if (project in bugsData) bugsData[project] += bugs;
            }
        });

        const bugsChartData = Object.entries(bugsData).map(([project, bugs]) => ({ project, bugs }));
        if (bugsChartData.length > 0) {
            try {
                const bugsPlot = Plot.plot({
                    title: "Bugs Found by Project",
                    x: { label: "Project", domain: bugsChartData.map(d => d.project) },
                    y: { label: "Number of Bugs" },
                    marks: [
                        BarY(bugsChartData, { x: "project", y: "bugs", fill: "#ef4444", title: "Bugs Found" })
                    ],
                    width: 800,
                    height: 400
                });
                const el = document.getElementById('bugs-chart');
                if (el) { el.innerHTML = ''; el.appendChild(bugsPlot); }
            } catch (error) {
                const el = document.getElementById('bugs-chart');
                if (el) el.innerHTML = '<p class="text-red-500">' + error.message + '</p>';
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
