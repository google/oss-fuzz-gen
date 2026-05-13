#!/bin/bash

# Loop through all files in the current directory
for file in $1/*; do
    # Ensure we are only processing files (not directories)
    if [ -f "$file" ]; then
        
        # Get the basename (e.g., "test.c" -> "test")
        # Use ${file%.*} to strip the extension
        name_base=$(basename "${file%.*}")

        # Use sed to replace the string
        # We use ':' as a delimiter because the search pattern has '//'
        sed -i "
            s|Dwarf_Debug dummy_debug;|Dwarf_Debug dummy_debug_${name_base};|g;
            s|Dwarf_Error dummy_error;|Dwarf_Error dummy_error_${name_base};|g;
            s|&dummy_debug|\&dummy_debug_${name_base}|g;
            s|&dummy_error|\&dummy_error_${name_base}|g
        " "$file"
        
        echo "Processed $file using base: $name_base"
    fi
done