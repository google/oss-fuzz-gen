// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

const BASE_URL = 'https://llm-exp.oss-fuzz.com/trend-reports';

class Dropdown {
  constructor(values, element, selectedValues) {
    this.values = values;
    this.element = element;
    this.selectedValues = selectedValues;

    // DOM elements
    this.inputElem = element.querySelector('input');
    this.dropdownElem = document.createElement('div');
    this.dropdownElem.className = 'filter-autocomplete';
    this.dropdownElem.style.display = 'none';
    this.selectedContainer = document.createElement('div');
    this.selectedContainer.className = 'selected-values';
    this.element.appendChild(this.dropdownElem);
    this.element.appendChild(this.selectedContainer);

    // Add chips for pre-selected values
    for (let value of selectedValues) {
      this.addSelectedValueChip(value);
    }

    // Misc
    this.hoveredValueElem = null;

    this.updateDropdown();

    // Show the dropdown while input is focused.
    this.inputElem.addEventListener('focus', () => {
      this.dropdownElem.style.display = '';
      if (this.dropdownElem.children.length > 0) {
        this.changeHovered(this.dropdownElem.children[0]);
      }
    });
    this.inputElem.addEventListener('blur', () => {
      this.dropdownElem.style.display = 'none';
    });
    // Update the dropdown values when the input value changes.
    this.inputElem.addEventListener('input', () => {
      this.updateDropdown();
      if (this.dropdownElem.children.length > 0) {
        this.changeHovered(this.dropdownElem.children[0]);
      }
    });
    // Up and down arrows move the dropdown selection and enter selects the
    // current selection.
    this.inputElem.addEventListener('keydown', (e) => {
      if (e.key === 'ArrowDown') {
        if (this.hoveredValueElem.nextElementSibling) {
          this.changeHovered(this.hoveredValueElem.nextElementSibling);
        }
      } else if (e.key === 'ArrowUp') {
        if (this.hoveredValueElem.previousElementSibling) {
          this.changeHovered(this.hoveredValueElem.previousElementSibling);
        }
      } else if (e.key === 'Enter') {
        this.selectValue(this.hoveredValueElem.innerText);
      } else if (e.key === 'Escape') {
        this.inputElem.blur();
      }
    });
  }

  // changeHovered changes the hovered (i.e. highlighted) dropdown value. It's
  // triggered by mouse hover or keyboard arrow keys.
  changeHovered(newHovered) {
    if (this.hoveredValueElem) {
      this.hoveredValueElem.classList.remove('hovered');
    }
    newHovered.classList.add('hovered');
    this.hoveredValueElem = newHovered;
  };

  // selectValue selects a dropdown value and adds it to the selectedValues
  // (i.e. page-wide filters). It also updates the dropdown to remove the
  // already selected value and adds a chip for the selected value so the user
  // is able to unselect the value (i.e. clear the filter).
  selectValue(value) {
    this.selectedValues.add(value);
    this.inputElem.value = '';
    this.updateDropdown();
    if (this.dropdownElem.children.length > 0) {
      this.changeHovered(this.dropdownElem.children[0]);
    }
    this.addSelectedValueChip(value);
  }

  // addSelectedValueChip adds a chip element to allow the user to remove a
  // selected value.
  addSelectedValueChip(value) {
    const selectedElem = document.createElement('span');
    selectedElem.className = 'chip';
    selectedElem.innerText = value;
    const crossIcon = document.createElement('button');
    crossIcon.className = 'material-symbols-outlined';
    crossIcon.innerText = 'close';
    selectedElem.appendChild(crossIcon);
    this.selectedContainer.appendChild(selectedElem);

    crossIcon.addEventListener('click', () => {
      this.selectedValues.delete(value);
      selectedElem.remove();
      this.updateDropdown();
    });
  }

  // updateDropdown is called when a value is selected/unselected and it's
  // responsible for repopulating the dropdown to update the list of values.
  updateDropdown() {
    this.dropdownElem.replaceChildren();
    for (let value of this.values) {
      // Only display values with matching substring.
      // Drop already selected values as well.
      if ((value.indexOf(this.inputElem.value) >= 0 || this.inputElem.value === '') && !this.selectedValues.has(value)) {
        const valElem = document.createElement('div');
        valElem.innerText = value;
        this.dropdownElem.appendChild(valElem);

        // We want to support selecting an element via mouse as well.
        // Selecting via keyboard is implemented on the input element.
        valElem.addEventListener('mouseover', () => {
          this.changeHovered(valElem);
        });
        valElem.addEventListener('mousedown', () => {
          this.selectValue(value);
        });
      }
    }
  }
}

class Page {
  constructor(index, filters) {
    this.index = index;
    this.sortedNames = Object.values(index).toSorted((a, b) => (new Date(a.date))-(new Date(b.date))).map(r => r.name);
    this.filters = filters;
    this.reports = new Map();

    this.setupFilters();
  }

  // setupFilter adds event listeners and other necessary configurations for
  // filter toggle, date range filter, and dropdown filters.
  setupFilters() {
    document.querySelector('#filters-toggle').addEventListener('click', () => {
      const filtersContainer = document.querySelector('#filters');
      if (filtersContainer.style.display === '') {
        filtersContainer.style.display = 'none';
      } else {
        filtersContainer.style.display = '';
      }
    });
    document.querySelector('#date-range-filter').addEventListener('change', (e) => {
      this.filters.dateRange = e.target.value;
      this.fetchAndUpdate();
    });

    // Set up dropdowns
    const tags = new Set();
    const benchmarkSets = new Set();
    const llmModels = new Set();
    for (let r of Object.values(this.index)) {
      for (let t of r.tags) {
        tags.add(t);
      }
      benchmarkSets.add(r.benchmark_set);
      llmModels.add(r.llm_model);

    }
    // Need to store `this.fetchAndUpdate` because inside the proxy `this` === `receiver`...
    const update = () => this.fetchAndUpdate();
    // We want to be notified when filters changed. We could force the dropdowns
    // to call a callback every time but instead we use a proxy to detect when
    // they call add/remove on the Set.
    const filtersProxyHandler = {
      get(target, prop, receiver) {
        if (prop === 'add' || prop === 'delete') {
          // Wait a "tick" and update the page once the set has been updated.
          window.requestAnimationFrame(update)
        }

        const value = Reflect.get(target, prop, receiver);
        // For Set.add/remove to work we need to replace the `this` argument
        // passed to the function. These functions access the `[[SetData]]`
        // internal slot which we can't redirect via a proxy. Replacing `this`
        // allows the javascript engine to correctly access the internal slots.
        if (value instanceof Function) {
          return value.bind(target);
        }
        return value;
      }
    };
    this.llmModelsDropdown = new Dropdown(
        Array.from(llmModels).toSorted(),
        document.querySelector('#llm-filter'),
        new Proxy(this.filters.llmModels, filtersProxyHandler));
    this.benchmarkSetsDropdown = new Dropdown(
        Array.from(benchmarkSets).toSorted(),
        document.querySelector('#benchmark-filter'),
        new Proxy(this.filters.benchmarkSets, filtersProxyHandler));
    this.tagsDropdown = new Dropdown(
        Array.from(tags).toSorted(),
        document.querySelector('#tag-filter'),
        new Proxy(this.filters.tags, filtersProxyHandler));
  }

  // fetchAndUpdate is called whenever filters change and it's responsible for
  // finding reports that match new filters and updating the rest of page to
  // show relevant data.
  async fetchAndUpdate() {
    document.querySelector('#loading').style.display = '';

    // Filter the list of reports
    let startDate = (new Date('1970-01-01')).getTime();
    if (this.filters.dateRange !== 'all') {
      const durationMillis = Number(this.filters.dateRange) * 3600 * 24 * 1000;
      startDate = Date.now() - durationMillis;
    }
    this.filteredNames = this.sortedNames.filter((name) => {
      const r = this.index[name];
      let tagsMatch = this.filters.tags.size == 0;
      for (let tag of r.tags) {
        if (this.filters.tags.has(tag)) {
          tagsMatch = true;
          break;
        }
      }
      return (
          startDate < (new Date(r.date)).getTime() &&
          tagsMatch &&
          (this.filters.llmModels.size == 0 || this.filters.llmModels.has(r.llm_model)) &&
          (this.filters.benchmarkSets.size == 0 || this.filters.benchmarkSets.has(r.benchmark_set)));
    });

    // Update the rest of the page. If no reports match, we'll just clear all
    // the children in each area. They do the same thing when the update methods
    // are called.
    if (this.filteredNames.length > 0) {
      this.updateReportLinks();
      await this.fetchReports();
      this.updateOverviewChart();
      this.updateOverviewTable();
      this.updateOverviewCoverageChart();
      this.updateProjectsAndData();
    } else {
      document.querySelector('#overview-chart').replaceChildren();
      document.querySelector('#overview-coverage-chart').replaceChildren();
      document.querySelector('#projects').replaceChildren();
      document.querySelector('#project-header').replaceChildren();
      document.querySelector('#project-coverage-chart').replaceChildren();
      document.querySelector('#project-coverage-table').replaceChildren();
      document.querySelector('#project-crash-chart').replaceChildren();
      document.querySelector('#links').replaceChildren();
    }
    document.querySelector('#loading').style.display = 'none';
  }

  // updateReportLinks updates the links sections with filtered reports.
  updateReportLinks() {
    // First reset the container before adding new reports.
    const linksElement = document.querySelector('#links');
    linksElement.replaceChildren();

    for (let n of this.filteredNames) {
      const r = this.index[n];

      const li = document.createElement('li');
      const reportLink = document.createElement('a');
      reportLink.innerText = `${r.directory}/${r.name}`;
      reportLink.href = r.url.endsWith('/') ? r.url : `${r.url}/`;
      reportLink.target = '_blank';
      li.appendChild(reportLink);
      linksElement.appendChild(li);
    }
  }

  // fetchReports fetches every filtered report not already cached in `this.reports`.
  async fetchReports() {
    const promises = [];
    for (let n of this.filteredNames) {
      if (!this.reports.has(n)) {
        const r = this.index[n];
        promises.push(fetch(`${BASE_URL}/${r.directory}/${n}.json`).then(res => res.json()).then(report => {
          this.reports.set(n, report);
        }));
      }
    }

    await Promise.all(promises);
  }

  // updateOverviewChart configures Plot to chart the coverage gain of different
  // projects across different reports.
  updateOverviewChart() {
    // First reset the container before adding the chart.
    const container = document.querySelector("#overview-chart");
    container.replaceChildren();

    const data = [];
    for (let n of this.filteredNames) {
      const report = this.reports.get(n);
      const toRate = (x) => {
        if (report.accumulated_results.total_runs == 0) {
          return 0;
        }
        return x / report.accumulated_results.total_runs * 100;
      }
      data.push({reportName: report.name, key: 'Build Rate %', value: toRate(report.accumulated_results.compiles)});
      data.push({reportName: report.name, key: 'Crash Cases', value: report.accumulated_results.crash_cases});
      data.push({reportName: report.name, key: 'Crashes', value: report.accumulated_results.crashes});
      data.push({reportName: report.name, key: 'Average Coverage %', value: toRate(report.accumulated_results.total_coverage)});
      data.push({reportName: report.name, key: 'Average Line Coverage Diff %', value: toRate(report.accumulated_results.total_line_coverage_diff)});
    }

    const chart = Plot.plot({
      width: container.clientWidth,
      color: {legend: true},
      // Remove y axis label since each line is a different value
      y: {label: null},
      // Rotate the report names (x scale) but also increase the bottom margin
      // so they're not cut off
      x: {label: null, tickRotate: -45},
      marginBottom: 200,
      marks: [
          Plot.ruleY([0]),
          Plot.lineY(data, {
            x: 'reportName',
            y: 'value',
            stroke: 'key',
            marker: 'circle',
            tip: true,
            sort: {x: null},
          }),
      ]
    });
    container.append(chart);
  }

  // ── new method to sum/average across all filtered experiments ─────────────
  computeAggregates() {
    let totalRuns       = 0;
    let totalCoverage   = 0;
    let totalCrashes    = 0;
    let totalCrashCases = 0;
    let totalExecTime   = 0;

    for (let name of this.filteredNames) {
      const rpt = this.reports.get(name).accumulated_results;
      totalRuns       += rpt.total_runs;
      totalCoverage   += rpt.total_coverage;
      totalCrashes    += rpt.crashes;
      totalCrashCases += rpt.crash_cases;
      totalExecTime   += (this.reports.get(name).execution_time || 0);
    }

    return {
      avgCoverage:  totalRuns
                      ? (totalCoverage / totalRuns) * 100
                      : 0,
      crashes:      totalCrashes,
      crashCases:   totalCrashCases,
      avgExecTime:  this.filteredNames.length
                      ? (totalExecTime / this.filteredNames.length)
                      : 0
    };
  }

  // ── Build the separate "Aggregated Metrics 📊" table ─────────────
  updateAggregatedMetrics() {
    const agg = this.computeAggregates();
    const container = document.querySelector('#aggregated-metrics');
    container.replaceChildren();

    // Heading
    const title = document.createElement('h3');
    title.innerText = 'Aggregated Metrics 📊';
    container.appendChild(title);

    // Table
    const table = document.createElement('table');
    const thead = document.createElement('thead');
    const tbody = document.createElement('tbody');
    table.appendChild(thead);
    table.appendChild(tbody);
    container.appendChild(table);

    // Header row
    const headerRow = document.createElement('tr');
    for (let h of ['Total Crashes', 'Total Crash Cases', 'Average Coverage', 'Execution Time']) {
      const th = document.createElement('th');
      th.innerText = h;
      headerRow.appendChild(th);
    }
    thead.appendChild(headerRow);

    // Data row
    const dataRow = document.createElement('tr');
    dataRow.innerHTML = `
      <td>${agg.crashes}</td>
      <td>${agg.crashCases}</td>
      <td>${agg.avgCoverage.toFixed(2)}%</td>
      <td>${agg.avgExecTime.toFixed(1)}s</td>
    `;
    tbody.appendChild(dataRow);
  }

  // updateOverviewTable updates the data table showing the coverage data for
  // the selected project.
  updateOverviewTable() {
    // First reset the container before creating the table again.
    const tableContainer = document.querySelector('#overview-table');
    tableContainer.replaceChildren();

    const table = document.createElement('table');
    const thead = document.createElement('thead');
    const tbody = document.createElement('tbody');
    const tfoot = document.createElement('tfoot');
    tfoot.id = 'overview-aggregate';

    table.appendChild(thead);
    table.appendChild(tbody);
    table.appendChild(tfoot);
    tableContainer.appendChild(table);


    for (let h of ['Report Name', 'Build Rate', 'Crashes', 'Crash Cases', 'Average Coverage', 'Average Line Coverage Diff']) {
      const th = document.createElement('th');
      th.innerText = h;
      thead.appendChild(th);
    }

    for (let n of this.filteredNames) {
      const tr = document.createElement('tr');
      tbody.appendChild(tr);

      const report = this.reports.get(n);
      const toRate = (x) => {
        if (report.accumulated_results.total_runs == 0) {
          return '0';
        }
        return (x / report.accumulated_results.total_runs * 100).toFixed(2);
      }
      const reportName = document.createElement('td');
      const reportLink = document.createElement('a');
      reportLink.innerText = report.name;
      reportLink.href = report.url.endsWith('/') ? report.url : `${report.url}/`;
      reportLink.target = '_blank';
      reportName.appendChild(reportLink);
      tr.appendChild(reportName);
      const buildRate = document.createElement('td');
      const buildRateVal = toRate(report.accumulated_results.compiles);
      buildRate.innerText = `${buildRateVal}%`;
      tr.appendChild(buildRate);
      const crashes = document.createElement('td');
      crashes.innerText = report.accumulated_results.crashes;
      tr.appendChild(crashes);
      const crashCases = document.createElement('td');
      crashCases.innerText = report.accumulated_results.crash_cases;
      tr.appendChild(crashCases);
      const coverage = document.createElement('td');
      const coverageVal = toRate(report.accumulated_results.total_coverage);
      coverage.innerText = `${coverageVal}%`;
      tr.appendChild(coverage);
      const lineCoverageDiff = document.createElement('td');
      const lineCoverageDiffVal = toRate(report.accumulated_results.total_line_coverage_diff);
      lineCoverageDiff.innerText = `${lineCoverageDiffVal}%`;
      tr.appendChild(lineCoverageDiff);
    }

    // ── inject the Total/Avg row into our new <tfoot> ─────────────
    this.updateAggregatedMetrics();
  }

  // updateOverviewCoverageChart configures Plot to chart the coverage gain of different
  // projects across different reports.
  updateOverviewCoverageChart() {
    // First reset the container before adding the chart.
    const container = document.querySelector("#overview-coverage-chart");
    container.replaceChildren();

    const data = [];
    for (let n of this.filteredNames) {
      const report = this.reports.get(n);
      for (let project of report.projects) {
        data.push({
          'Project Name': project.name,
          'Report Name': report.name,
          // Don't do *100 because the y axis is marked as a percentage.
          'Coverage Gain': project.coverage_gain,
          'Relative Coverage Gain %': project.coverage_relative_gain * 100,
        });
      }
    }

    const chart = Plot.plot({
      width: container.clientWidth,
      color: {legend: true},
      y: {label: 'Coverage Gain %', percent: true},
      // Rotate the report names (x scale) but also increase the bottom margin
      // so they're not cut off
      x: {label: null, tickRotate: -45},
      marginBottom: 200,
      marks: [
          Plot.ruleY([0]),
          Plot.lineY(data, {
            x: 'Report Name',
            y: 'Coverage Gain',
            stroke: 'Project Name',
            marker: 'circle',
            tip: true,
            channels: {'Relative Coverage Gain %': 'Relative Coverage Gain %'},
            sort: {x: null},
          }),
      ]
    });
    container.append(chart);
  }

  // updateProjectsAndData updates project selection section and related data
  // sections.
  updateProjectsAndData() {
    // List of projects for the project selector
    const projects = new Set();
    for (let n of this.filteredNames) {
      const report = this.reports.get(n);
      for (let p of report.projects) {
        projects.add(p.name);
      }
    }
    this.sortedProjects = Array.from(projects).toSorted((a, b) => a.localeCompare(b));
    this.selectedProject = this.sortedProjects[0];

    // First reset the container before adding new project chips.
    const projectsContainer = document.querySelector('#projects');
    projectsContainer.replaceChildren();

    for (let project of this.sortedProjects) {
      const projectChip = document.createElement('button');
      if (project == this.selectedProject) {
        projectChip.className = 'selected';
      }
      projectChip.innerText = project;
      projectChip.addEventListener('click', () => {
        this.selectedProject = project;
        projectsContainer.querySelector('.selected').className = '';
        projectChip.className = 'selected';
        this.updateProjectData();
      });
      projectsContainer.appendChild(projectChip);
    }

    this.updateProjectData();
  }

  // updateProjectData updates all the data section with project related data
  // e.g. project data table, charts, etc.
  updateProjectData() {
    document.querySelector('#project-header').innerText = `${this.selectedProject} Trends`;
    this.updateProjectCharts();
    this.updateProjectCoverageTable();
  }

  // updateProjectCharts configures Plot to chart coverage, build rate, crash
  // etc. from functions in the selected project across different reports.
  updateProjectCharts() {
    // First reset the container before adding the chart.
    const coverageContainer = document.querySelector("#project-coverage-chart");
    const crashContainer = document.querySelector("#project-crash-chart");
    const buildContainer = document.querySelector("#project-build-chart");
    coverageContainer.replaceChildren();
    crashContainer.replaceChildren();
    buildContainer.replaceChildren();

    const data = [];
    for (let n of this.filteredNames) {
      const report = this.reports.get(n);
      for (let benchmark of report.benchmarks) {
        if (benchmark.project === this.selectedProject) {
          data.push({
            reportName: report.name,
            signature: benchmark.signature,
            maxCoverage: benchmark.max_coverage,
            maxLineCoverageDiff: benchmark.max_line_coverage_diff,
            buildSuccessRate: benchmark.build_success_rate,
            crashRate: benchmark.crash_rate,
          });
        }
      }
    }

    const coverageChart = Plot.plot({
      width: coverageContainer.clientWidth,
      color: {legend: true},
      y: {label: 'Max Line Coverage Diff %', percent: true},
      // Rotate the report names (x scale) but also increase the bottom margin
      // so they're not cut off
      x: {label: null, tickRotate: -45},
      marginBottom: 200,
      marks: [
          Plot.ruleY([0]),
          Plot.lineY(data, {
            x: 'reportName',
            y: 'maxLineCoverageDiff',
            stroke: 'signature',
            marker: 'circle',
            tip: true,
            sort: {x: null},
          }),
      ]
    });
    coverageContainer.append(coverageChart);
    const crashChart = Plot.plot({
      width: crashContainer.clientWidth,
      color: {legend: true},
      y: {label: 'Crash Rate %', percent: true},
      // Rotate the report names (x scale) but also increase the bottom margin
      // so they're not cut off
      x: {label: null, tickRotate: -45},
      marginBottom: 200,
      marks: [
          Plot.ruleY([0]),
          Plot.lineY(data, {
            x: 'reportName',
            y: 'crashRate',
            stroke: 'signature',
            marker: 'circle',
            tip: true,
            sort: {x: null},
          }),
      ]
    });
    crashContainer.append(crashChart);
    const buildChart = Plot.plot({
      width: buildContainer.clientWidth,
      color: {legend: true},
      y: {label: 'Build Success Rate %', percent: true},
      // Rotate the report names (x scale) but also increase the bottom margin
      // so they're not cut off
      x: {label: null, tickRotate: -45},
      marginBottom: 200,
      marks: [
          Plot.ruleY([0]),
          Plot.lineY(data, {
            x: 'reportName',
            y: 'buildSuccessRate',
            stroke: 'signature',
            marker: 'circle',
            tip: true,
            sort: {x: null},
          }),
      ]
    });
    buildContainer.append(buildChart);
  }

  // updateProjectCoverageTable updates the data table showing the coverage data for
  // the selected project.
  updateProjectCoverageTable() {
    // First reset the container before creating the table again.
    const tableContainer = document.querySelector('#project-coverage-table');
    tableContainer.replaceChildren();

    const table = document.createElement('table');
    const thead = document.createElement('thead');
    const tbody = document.createElement('tbody');
    table.appendChild(thead);
    table.appendChild(tbody);
    tableContainer.appendChild(table);

    const signatureSet = new Set();
    for (let n of this.filteredNames) {
      const report = this.reports.get(n);
      for (let benchmark of report.benchmarks) {
        if (benchmark.project === this.selectedProject) {
          signatureSet.add(benchmark.signature);
        }
      }
    }
    const signatures = Array.from(signatureSet).toSorted();

    // The header spans two rows. First two cells span two rows then a cell
    // spanning multiple columns, 'Line Coverage Diff'. Under that a cell for
    // each signature.
    const headerTr1 = document.createElement('tr');
    thead.appendChild(headerTr1);
    for (let h of ['Report', 'Overall Coverage Gain']) {
      const th = document.createElement('th');
      th.innerText = h;
      th.rowSpan = 2;
      headerTr1.appendChild(th);
    }
    const lineDiffTh = document.createElement('th');
    lineDiffTh.innerText = 'Line Coverage Diff';
    lineDiffTh.colSpan = signatures.length;
    lineDiffTh.style.textAlign = 'center';
    headerTr1.appendChild(lineDiffTh);

    const headerTr2 = document.createElement('tr');
    thead.appendChild(headerTr2);
    for (let sig of signatures) {
      const th = document.createElement('th');
      th.innerText = sig;
      headerTr2.appendChild(th);
    }

    for (let n of this.filteredNames) {
      const report = this.reports.get(n);
      const project = report.projects.find(p => p.name === this.selectedProject);
      if (project) {
        const rowElem = document.createElement('tr');
        tbody.appendChild(rowElem);

        const reportElem = document.createElement('td');
        const reportLink = document.createElement('a');
        reportLink.innerText = report.name;
        reportLink.href = report.url.endsWith('/') ? report.url : `${report.url}/`;
        reportLink.target = '_blank';
        reportElem.appendChild(reportLink);
        rowElem.appendChild(reportElem);
        const coverageElem = document.createElement('td');
        coverageElem.innerText = `${(project.coverage_gain * 100).toFixed(2)}%`;
        rowElem.appendChild(coverageElem);

        for (let sig of signatures) {
          const sigElem = document.createElement('td');
          rowElem.appendChild(sigElem);

          const benchmark = report.benchmarks.find(b => b.signature === sig);
          if (benchmark) {
            sigElem.innerText = `${(benchmark.max_line_coverage_diff * 100).toFixed(2)}%`;
          }
        }
      }
    }
  }
}


async function main() {
  const index = await (await fetch(`${BASE_URL}/index.json`)).json();

  const filters = {
    dateRange: 'all',
    llmModels: new Set(),
    benchmarkSets: new Set(),
    tags: new Set(['daily']),
  };
  const page = new Page(index, filters);
  await page.fetchAndUpdate();
}

main();
