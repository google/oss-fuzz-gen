document.addEventListener('DOMContentLoaded', function() {
    // Summary table expand/collapse buttons
    const summaryExpandAllButton = document.getElementById('summary-expand-all');
    if (summaryExpandAllButton) {
        summaryExpandAllButton.addEventListener('click', () => {
            document.querySelectorAll('[x-ref^="benchmarks_"]').forEach(el => {
                el.classList.remove('hidden');
            });
        });
    }

    const summaryCollapseAllButton = document.getElementById('summary-collapse-all');
    if (summaryCollapseAllButton) {
        summaryCollapseAllButton.addEventListener('click', () => {
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

    const tocTree = document.getElementById('toc-tree');
    const sections = document.querySelectorAll('.toc-section');
    sections.forEach((section, index) => {
        const sectionLi = document.createElement('li');
        const sectionLink = document.createElement('a');
        const sectionTitle = section.querySelector('.text-lg.font-bold');
        sectionLink.textContent = sectionTitle.textContent.trim();
        sectionLink.href = `#section-${index}`;
        sectionLink.className = 'toc-link toc-section';
        section.id = `section-${index}`;
        sectionLi.appendChild(sectionLink);

        const subsectionButtons = section.querySelectorAll('button.toc-subsection');
        if (subsectionButtons.length > 0) {
            const subsectionsUl = document.createElement('ul');
            
            subsectionButtons.forEach(subsectionBtn => {
                const subsectionName = subsectionBtn.textContent.trim();
                const subsectionLi = document.createElement('li');
                const subsectionLink = document.createElement('a');
                subsectionLink.textContent = subsectionName;
                subsectionLink.href = `#subsection-${subsectionName}`;
                subsectionLink.className = 'toc-link toc-subsection';
                subsectionLi.appendChild(subsectionLink);

                const subsectionRow = subsectionBtn.closest('tr');
                const itemsContainer = subsectionRow ? subsectionRow.nextElementSibling : null;
                
                if (itemsContainer) {
                    const itemButtons = itemsContainer.querySelectorAll('button.toc-item');
                    const itemLinks = itemsContainer.querySelectorAll('pre.signature.toc-item a');
                    
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
                            itemLink.className = 'toc-link toc-item prettify-benchmark-name';
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
                            itemLink.className = 'toc-link toc-item prettify-benchmark-name';
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

    // Toggle functionality
    const toc = document.getElementById('toc');
    const tocToggle = document.getElementById('tocToggle');

    tocToggle.addEventListener('click', () => {
        toc.classList.toggle('open');
        tocToggle.classList.toggle('open');
    });

    document.addEventListener('click', (e) => {
        if (!toc.contains(e.target) && !tocToggle.contains(e.target) && toc.classList.contains('open')) {
            toc.classList.remove('open');
            tocToggle.classList.remove('open')
        }
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

                if (table_element.id === 'summary-table') {
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
