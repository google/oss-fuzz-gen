# Fix: Benchmark Table Lacks Clear Default Sorting Behavior

## Issue #1003

### Problem

The benchmark table on `benchmark.html` lacked:

- Clear default sorting behavior
- Ability to sort columns manually by clicking headers
- Visual indication of sort direction

### Solution

This PR implements comprehensive table sorting functionality:

1. **Default Sorting**: Tables now default to sorting by "Coverage" column in descending order (highest coverage first)

2. **Interactive Sorting**: All column headers (except the first empty column) are now clickable and allow sorting in both ascending and descending order

3. **Visual Indicators**:

   - Hover effects on clickable headers
   - Sort direction arrows (▼ for ascending, ▲ for descending)
   - Proper cursor styling

4. **Smart Sorting Logic**:

   - Numeric columns (marked with `data-sort-number`) sort numerically
   - Percentage values are parsed correctly (e.g., "85.6%" → 85.6)
   - Boolean values (True/False) sort correctly
   - String columns sort alphabetically (case-insensitive)
   - Uses `data-sort-value` attributes when available for precise sorting

5. **Accessibility**:
   - Headers have proper hover states
   - Row indices update automatically after sorting
   - Keyboard navigation support

### Files Modified

#### `report/templates/benchmark/benchmark.html`

- Removed hardcoded `data-sorted="asc"` from Sample column
- Table structure remains unchanged

#### `report/templates/benchmark/benchmark.js`

- Added `initTableSorting()` function
- Added `sortTable()` function with smart type detection
- Added `updateRowIndices()` function
- Integrated table sorting initialization into DOMContentLoaded event

#### `report/templates/benchmark/benchmark.css`

- Enhanced header hover effects
- Added transition animations
- Improved user-select handling with vendor prefixes
- Added dark mode hover support
- Made first column non-clickable (as it's just an index)

### Usage

- **Default Behavior**: Table loads sorted by Coverage (highest first)
- **Manual Sorting**: Click any column header to sort by that column
- **Toggle Direction**: Click the same header again to reverse sort direction
- **Visual Feedback**: Arrows show current sort direction, hover effects indicate clickable headers

### Testing

A test file (`test_table_sorting.html`) has been included to verify the functionality works with sample data.

### Compatibility

- Works with existing table structure
- Supports both light and dark modes
- Cross-browser compatible (includes vendor prefixes)
- Mobile-friendly (responsive design maintained)

This enhancement significantly improves the user experience when analyzing benchmark results, making it easy to quickly find the most relevant trials based on different criteria.
