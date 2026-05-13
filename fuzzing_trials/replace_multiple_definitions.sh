
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 FUNCTION_NAME SOURCE_DIR"
    exit 1
fi

FUNC="$1"
SRC_DIR="$2"

for file in $SRC_DIR/*; do
    base=$(basename "$file")
    suffix="${base%.*}"
    NEW_NAME="${FUNC}_${suffix}"
    sed -i -E "s/\b${FUNC}\b/${NEW_NAME}/g" "$file"
done