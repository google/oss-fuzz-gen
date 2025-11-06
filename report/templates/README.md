# Report Templates

## Overview

An experiment report consists of three main page types: Index, Benchmark, and Sample.

* Index: Aggregated results across all benchmarks and projects
* Benchmark: Results for all samples in a single benchmark
* Sample: Detailed logs and crash analysis for a single sample

All pages extend `base.html` and share common assets. Static files are injected into templates via `web.py`:

* `shared_css_content` - Injected into all pages via base.html
* `base_js_content` - Injected into all pages via base.html
* `{page}_css_content` - Page-specific CSS (index, benchmark, sample)
* `{page}_js_content` - Page-specific JS (index, benchmark, sample)

## File Structure

```
templates/
├── base.html           - Base layout with header, navigation, search
├── base.js             - Search, TOC, prettifyBenchmarkName, syntax highlighting
├── shared.css          - Common table and chart styles
├── macros.html         - Reusable Jinja2 UI components
├── index/              - Main experiment summary index page
│   ├── index.html      
│   ├── index.js        
│   └── index.css       
├── benchmark/          - Per-benchmark detail page
│   ├── benchmark.html  
│   ├── benchmark.js    
│   └── benchmark.css   
└── sample/             - Per-sample detail page
    ├── sample.html     
    ├── sample.js       
    └── sample.css      

```

# Updating Template Code

## Adding New Pages

1. Create `{page}/{page}.html`, `{page}.js`, `{page}.css` in templates/
2. Add `_write_{page}` method in `web.py` following existing pattern
3. Call `self._read_static_file('{page}/{page}.js')` and pass as `{page}_js_content`
4. Add to `generate()` method pipeline

## Extending Search Functionality

* To modify field weights: Adjust `BASE_SEARCH_FIELD_WEIGHTS` in `base.js`
* To add searchable fields: Extend `fields` array in `searchSamples()` 
* To update the scoring algorithm: Modify score calculation in `searchSamples()` loop
* To add new fields to the data structure: Update `_build_unified_data()` in `web.py` to include new fields

## Table of Contents

* The table of contents is auto-generated from elements with `.toc-section`, `.toc-subsection`, `.toc-item` CSS classes.
* The builder in `base.js:buildTOC()` creates a hierarchical tree: Sections -> Subsections -> Items. 
* To add elements to the table of contents, you can apply the appropriate CSS class to any button/header.