document.addEventListener('DOMContentLoaded', function() {
    const expandAllButton = document.getElementById('expand-all');
    if (expandAllButton) {
        expandAllButton.addEventListener('click', () => {
            document.querySelectorAll('[x-ref^="benchmarks_"]').forEach(el => {
                el.classList.remove('hidden');
            });
        });
    }

    const collapseAllButton = document.getElementById('collapse-all');
    if (collapseAllButton) {
        collapseAllButton.addEventListener('click', () => {
            document.querySelectorAll('[x-ref^="benchmarks_"]').forEach(el => {
                el.classList.add('hidden');
            });
        });
    }

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

                if (table_element.id === 'summary-table') {
                    let projectPairs = [];
                    let allRows = Array.from(tbody.children);
                    for (let i = 0; i < allRows.length; i += 2) {
                        if (allRows[i] && allRows[i+1] &&
                            allRows[i].classList.contains('project-data-row') &&
                            allRows[i+1].classList.contains('project-benchmarks-container-row')) {
                            projectPairs.push({ dataRow: allRows[i], containerRow: allRows[i+1] });
                        }
                    }

                    projectPairs.sort((pairA, pairB) => {
                        return compareTableCells(pairA.dataRow.children[colindex], pairB.dataRow.children[colindex], sortNumber, sortAsc);
                    });

                    tbody.innerHTML = '';
                    projectPairs.forEach(pair => {
                        tbody.appendChild(pair.dataRow);
                        tbody.appendChild(pair.containerRow);
                    });
                } else {
                    let rows = Array.from(tbody.children);
                    let averageRow = null;

                    if (table_element.id && table_element.id.startsWith('benchmarks-table-')) {
                        const averageRowIndex = rows.findIndex(row => row.cells.length > 0 && row.cells[0].innerText.trim() === 'Average');
                        if (averageRowIndex !== -1) {
                            averageRow = rows.splice(averageRowIndex, 1)[0];
                        }
                    }

                    rows.sort((a, b) => {
                        return compareTableCells(a.children[colindex], b.children[colindex], sortNumber, sortAsc);
                    });

                    tbody.innerHTML = '';
                    rows.forEach(row => tbody.appendChild(row));
                    if (averageRow) {
                        tbody.appendChild(averageRow);
                    }

                    let visualIndex = 1;
                    Array.from(tbody.children).forEach(r => {
                        if (averageRow && r === averageRow) {
                            return; 
                        }
                        const firstCell = r.children[0];
                        if (firstCell && firstCell.classList.contains('table-index') && !firstCell.querySelector('button')) {
                             firstCell.innerText = visualIndex++;
                        }
                    });
                }
            });
        });
    });
});
