document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('expand-all').addEventListener('click', () => {
        document.querySelectorAll('[x-ref^="benchmarks_"]').forEach(el => {
            el.classList.remove('hidden');
        });
    });

    document.getElementById('collapse-all').addEventListener('click', () => {
        document.querySelectorAll('[x-ref^="benchmarks_"]').forEach(el => {
            el.classList.add('hidden');
        });
    });
});

(function() {
    tables = Array.from(document.querySelectorAll('table.sortable-table'));
    for (let tbl_idx1 = 0; tbl_idx1 < tables.length; tbl_idx1++) {
        table_element = tables[tbl_idx1];
        const table_id_name = table_element.id;
        headers = Array.from(table_element.querySelectorAll('th'));
        headers.map(
            (th, colindex) => th.addEventListener('click', () => {
                const sortAsc = th.dataset.sorted != "asc";
                const sortNumber = th.dataset.sortNumber != undefined;

                // Move sorted data attribute to the right column
                headers.map(innerTH => delete innerTH.dataset.sorted);
                th.dataset.sorted = sortAsc ? "asc" : "desc";

                // Find the relevant table and sort it accordingly.
                inner_tables = Array.from(document.querySelectorAll('table.sortable-table'));
                for (let tbl_idx2 = 0; tbl_idx2 < inner_tables.length; tbl_idx2++) {
                    the_table = inner_tables[tbl_idx2];
                    if (the_table.id == table_id_name) {
                        const tbody = the_table.querySelector('tbody');
                        const rows = Array.from(tbody.children);
                        rows.sort((a, b) => {
                            let [valueA, valueB] = [a.children[colindex].dataset.sortValue, b.children[colindex].dataset.sortValue];
                            // Swap the values for descending.
                            if (!sortAsc) {
                                [valueB, valueA] = [valueA, valueB];
                            }

                            if (sortNumber) {
                                return Number(valueB) - Number(valueA);
                            }
                            return valueA.localeCompare(valueB);
                        });
                        tbody.replaceChildren(...rows);
                        // Rewrite the index column
                        rows.map((r, i) => r.children[0].innerText = i);
                    }
                }
            }, )
        );

    }
})();
