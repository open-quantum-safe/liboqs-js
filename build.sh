#!/bin/bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/builds-wasm"
OUTPUT_DIR="$SCRIPT_DIR/dist"
BUILD_JOBS=2
ALGORITHM_REGISTRY="$SCRIPT_DIR/algorithms.json"

LIBOQS_BRANCH="${LIBOQS_BRANCH:-main}"
LIBOQS_DIR="$SCRIPT_DIR/liboqs"
LIBOQS_REPO="https://github.com/open-quantum-safe/liboqs.git"

KEM_FAMILIES="ML_KEM KYBER CLASSIC_MCELIECE FRODOKEM HQC NTRU NTRUPRIME"
SIG_FAMILIES="ML_DSA FALCON SLH_DSA CROSS MAYO UOV SNOVA"

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

get_algorithm_data() {
    local slug=$1
    local field=$2
    jq -r --arg slug "$slug" --arg field "$field" '
        (.kem, .sig, ."sig-stateful") | .. |
        select(type == "object" and .slug? == $slug) |
        .[$field]
    ' "$ALGORITHM_REGISTRY" | head -1
}

get_algorithm_type() {
    local slug=$1
    # Check if algorithm is in .kem, otherwise it's in .sig or .sig-stateful (both are "sig" type)
    if jq -e --arg slug "$slug" '.kem | .. | select(type == "object" and .slug? == $slug)' "$ALGORITHM_REGISTRY" > /dev/null 2>&1; then
        echo "kem"
    else
        echo "sig"
    fi
}

get_algorithm_family() {
    local slug=$1
    jq -r --arg slug "$slug" '
        to_entries[] | select(.key == "kem" or .key == "sig" or .key == "sig-stateful") |
        .value | to_entries[] |
        select(.value | to_entries[] | .value.slug? == $slug) |
        .key
    ' "$ALGORITHM_REGISTRY" | head -1 | tr '[:lower:]-' '[:upper:]_'
}

get_all_algorithm_slugs() {
    jq -r '.kem, .sig, ."sig-stateful" | .. | .slug? | select(. != null)' "$ALGORITHM_REGISTRY"
}

get_all_kem_slugs() {
    jq -r '.kem | .. | .slug? | select(. != null)' "$ALGORITHM_REGISTRY"
}

get_all_sig_slugs() {
    jq -r '.sig, ."sig-stateful" | .. | .slug? | select(. != null)' "$ALGORITHM_REGISTRY"
}

get_all_kem_cmake_vars() {
    jq -r '.kem | .. | .cmake_var? | select(. != null)' "$ALGORITHM_REGISTRY"
}

get_all_sig_cmake_vars() {
    jq -r '.sig, ."sig-stateful" | .. | .cmake_var? | select(. != null)' "$ALGORITHM_REGISTRY"
}

setup_liboqs() {
    log_info "Setting up LibOQS repository..."

    if [ -d "$LIBOQS_DIR" ]; then
        log_info "Removing existing LibOQS directory for clean clone..."
        rm -rf "$LIBOQS_DIR"
    fi

    log_info "Cloning LibOQS from $LIBOQS_REPO..."
    git clone --depth 1 --branch "$LIBOQS_BRANCH" "$LIBOQS_REPO" "$LIBOQS_DIR"

    local commit=$(git -C "$LIBOQS_DIR" rev-parse HEAD)
    local short_commit=$(git -C "$LIBOQS_DIR" rev-parse --short HEAD)
    log_success "LibOQS ready: $short_commit ($commit)"
}

get_core_functions() {
    local alg_type=$1
    local core_minimal='["_malloc","_free","_OQS_init","_OQS_destroy"'

    case $alg_type in
        "kem")
            echo "$core_minimal"',
                  "_OQS_MEM_malloc","_OQS_MEM_secure_free","_OQS_randombytes",
                  "_OQS_KEM_new","_OQS_KEM_free","_OQS_KEM_keypair",
                  "_OQS_KEM_encaps","_OQS_KEM_decaps"]'
            ;;
        "sig")
            echo "$core_minimal"',
                  "_OQS_MEM_malloc","_OQS_MEM_secure_free","_OQS_randombytes",
                  "_OQS_MEM_cleanse","_OQS_SIG_new","_OQS_SIG_free",
                  "_OQS_SIG_keypair","_OQS_SIG_sign","_OQS_SIG_verify"]'
            ;;
        *)
            echo "$core_minimal"']'
            ;;
    esac
}

get_algorithm_cmake_flags() {
    local target_slug=$1
    local flags=""

    # Get target algorithm info
    local target_cmake_var=$(get_algorithm_data "$target_slug" "cmake_var")
    if [ -z "$target_cmake_var" ]; then
        log_error "Algorithm not found in registry: $target_slug"
        return 1
    fi

    local alg_type=$(get_algorithm_type "$target_slug")
    local target_family=$(get_algorithm_family "$target_slug")

    # Disable all individual algorithms EXCEPT the target
    for cmake_var in $(get_all_kem_cmake_vars); do
        if [ "$cmake_var" != "$target_cmake_var" ]; then
            flags="$flags -DOQS_ENABLE_KEM_${cmake_var}=OFF"
        fi
    done

    for cmake_var in $(get_all_sig_cmake_vars); do
        if [ "$cmake_var" != "$target_cmake_var" ]; then
            flags="$flags -DOQS_ENABLE_SIG_${cmake_var}=OFF"
        fi
    done

    # Disable all algorithm families EXCEPT the one containing the target
    for family in $KEM_FAMILIES; do
        if [ "$family" != "$target_family" ]; then
            flags="$flags -DOQS_ENABLE_KEM_${family}=OFF"
        else
            flags="$flags -DOQS_ENABLE_KEM_${family}=ON"
        fi
    done

    for family in $SIG_FAMILIES; do
        if [ "$family" != "$target_family" ]; then
            flags="$flags -DOQS_ENABLE_SIG_${family}=OFF"
        else
            flags="$flags -DOQS_ENABLE_SIG_${family}=ON"
        fi
    done

    flags="$flags -DOQS_ENABLE_SIG_STFL_XMSS=OFF"
    flags="$flags -DOQS_ENABLE_SIG_STFL_LMS=OFF"

    # Enable target algorithm
    case $alg_type in
        "kem")
            flags="$flags -DOQS_ENABLE_KEM_${target_cmake_var}=ON"
            ;;
        "sig")
            flags="$flags -DOQS_ENABLE_SIG_${target_cmake_var}=ON"
            ;;
        *)
            log_error "Unknown algorithm type for: $target_slug"
            return 1
            ;;
    esac

    echo "$flags"
}

emit_wasm_module() {
    local static_lib=$1
    local output_file=$2
    local export_name=$3
    local export_file=$4
    local environment=$5

    emcc "$static_lib" \
        -o "$output_file" \
        -s WASM=1 \
        -s MODULARIZE=1 \
        -s EXPORT_NAME="$export_name" \
        -s EXPORT_ES6=1 \
        -s SINGLE_FILE=1 \
        -s ENVIRONMENT="$environment" \
        -s EXPORTED_FUNCTIONS="@$export_file" \
        -s EXPORTED_RUNTIME_METHODS='["ccall","cwrap","getValue","setValue","UTF8ToString","stringToUTF8","lengthBytesUTF8","HEAPU8","HEAP32"]' \
        -s ALLOW_MEMORY_GROWTH=1 \
        -s INITIAL_MEMORY=8519680 \
        -s MAXIMUM_MEMORY=268435456 \
        -s STACK_SIZE=8392064 \
        -s SUPPORT_BIG_ENDIAN=0 \
        -s MALLOC="emmalloc" \
        -s FILESYSTEM=0 \
        -s ASSERTIONS=0 \
        -s SAFE_HEAP=0 \
        -msimd128 \
        -O3 \
        --closure 1 \
        --no-entry
}

build_algorithm() {
    local slug=$1

    log_info "Building $slug..."

    local alg_type=$(get_algorithm_type "$slug")
    if [ -z "$alg_type" ]; then
        log_error "Algorithm not found in registry: $slug"
        return 1
    fi

    local build_dir="$BUILD_DIR/$slug"
    local install_dir="$build_dir/install"

    rm -rf "$build_dir"
    mkdir -p "$build_dir" "$install_dir"

    local export_file="$build_dir/exported_functions.json"
    get_core_functions "$alg_type" > "$export_file"

    local cmake_flags
    cmake_flags=$(get_algorithm_cmake_flags "$slug")

    # Run cmake/make in a subshell to avoid leaking working directory
    (
        cd "$build_dir"

        log_info "Configuring $slug..."
        emcmake cmake "$LIBOQS_DIR" \
            -DCMAKE_BUILD_TYPE=Release \
            -DCMAKE_INSTALL_PREFIX="$install_dir" \
            -DBUILD_SHARED_LIBS=OFF \
            -DOQS_BUILD_ONLY_LIB=ON \
            -DOQS_DIST_BUILD=OFF \
            -DOQS_USE_OPENSSL=OFF \
            -DOQS_PERMIT_UNSUPPORTED_ARCHITECTURE=ON \
            $cmake_flags \
            -DCMAKE_C_FLAGS="-O3" \
            2>&1 | grep -v "Manually-specified variables were not used by the project" || true

        log_info "Building $slug..."
        emmake make -j$BUILD_JOBS

        log_info "Installing $slug..."
        make install
    )

    local static_lib
    static_lib=$(find "$install_dir" -name "liboqs.a" -type f | head -1)

    if [ -z "$static_lib" ] || [ ! -f "$static_lib" ]; then
        log_error "Static library not found for $slug"
        return 1
    fi

    log_info "Creating WASM module for $slug..."
    mkdir -p "$OUTPUT_DIR"

    local export_name="LibOQS_$(echo $slug | tr '-' '_')"

    log_info "Building Node.js module for $slug..."
    emit_wasm_module "$static_lib" "$OUTPUT_DIR/$slug.min.js" "$export_name" "$export_file" "web,worker,webview,node"

    log_info "Building Deno module for $slug..."
    emit_wasm_module "$static_lib" "$OUTPUT_DIR/$slug.deno.js" "$export_name" "$export_file" "web"

    if [ -f "$OUTPUT_DIR/$slug.min.js" ] && [ -f "$OUTPUT_DIR/$slug.deno.js" ]; then
        local node_size=$(ls -lh "$OUTPUT_DIR/$slug.min.js" | awk '{print $5}')
        local deno_size=$(ls -lh "$OUTPUT_DIR/$slug.deno.js" | awk '{print $5}')

        log_success "Successfully built $slug:"
        log_info "  Node.js: $node_size"
        log_info "  Deno: $deno_size"
        return 0
    else
        log_error "Failed to generate WASM modules for $slug"
        return 1
    fi
}

cleanup() {
    log_info "Cleaning up build artifacts..."
    [ -d "$BUILD_DIR" ] && rm -rf "$BUILD_DIR"
}

main() {
    log_info "LibOQS WASM Modular Builder"
    log_info "==========================="

    local build_type="${1:-all}"
    local parallel_jobs="${PARALLEL_JOBS:-4}"

    setup_liboqs
    mkdir -p "$OUTPUT_DIR"

    local algorithms=()

    case "$build_type" in
        --kem)
            log_info "Building KEM algorithms only"
            mapfile -t algorithms < <(get_all_kem_slugs)
            ;;
        --sig)
            log_info "Building SIG algorithms only"
            mapfile -t algorithms < <(get_all_sig_slugs)
            ;;
        all)
            mapfile -t algorithms < <(get_all_algorithm_slugs)
            ;;
        *)
            algorithms=("$build_type")
            ;;
    esac

    local successful=0
    local failed=()

    if [ ${#algorithms[@]} -gt 1 ] && command -v parallel >/dev/null 2>&1; then
        log_info "Building ${#algorithms[@]} algorithms in parallel (${parallel_jobs} jobs at a time)..."

        export -f build_algorithm get_algorithm_data get_algorithm_type get_algorithm_cmake_flags
        export -f get_core_functions get_all_kem_cmake_vars get_all_sig_cmake_vars
        export -f get_algorithm_family emit_wasm_module
        export -f log_info log_success log_warn log_error
        export BUILD_DIR OUTPUT_DIR BUILD_JOBS ALGORITHM_REGISTRY LIBOQS_DIR
        export KEM_FAMILIES SIG_FAMILIES
        export RED GREEN YELLOW BLUE NC

        # Use --bar only if we have a TTY, otherwise use line-buffered output
        # --halt now,fail=1 stops on first failure and returns non-zero exit code
        if [ -t 1 ]; then
            printf '%s\n' "${algorithms[@]}" | parallel -j "$parallel_jobs" --halt now,fail=1 --bar build_algorithm {}
        else
            printf '%s\n' "${algorithms[@]}" | parallel -j "$parallel_jobs" --halt now,fail=1 --line-buffer build_algorithm {}
        fi

        for algorithm in "${algorithms[@]}"; do
            if [ -f "$OUTPUT_DIR/$algorithm.min.js" ]; then
                successful=$((successful + 1))
            else
                failed+=("$algorithm")
            fi
        done
    else
        # Fallback to parallel background jobs if GNU parallel not available
        if [ ${#algorithms[@]} -gt 1 ]; then
            log_info "Building ${#algorithms[@]} algorithms in parallel (${parallel_jobs} jobs, background mode)..."

            local -A pid_to_alg
            local pids=()
            local running=0

            for algorithm in "${algorithms[@]}"; do
                # Wait if we've hit the parallel job limit
                while [ $running -ge $parallel_jobs ]; do
                    sleep 0.1
                    # Check finished jobs
                    for i in "${!pids[@]}"; do
                        if ! kill -0 "${pids[$i]}" 2>/dev/null; then
                            unset "pids[$i]"
                            running=$((running - 1))
                        fi
                    done
                done

                (build_algorithm "$algorithm") &
                local pid=$!
                pids+=($pid)
                pid_to_alg[$pid]="$algorithm"
                running=$((running + 1))
            done

            # Wait for all remaining jobs and check exit codes
            for pid in "${pids[@]}"; do
                local alg="${pid_to_alg[$pid]:-unknown}"
                if wait "$pid"; then
                    successful=$((successful + 1))
                else
                    failed+=("$alg")
                fi
            done
        else
            for algorithm in "${algorithms[@]}"; do
                if build_algorithm "$algorithm"; then
                    successful=$((successful + 1))
                else
                    failed+=("$algorithm")
                fi
                echo "----------------------------------------"
            done
        fi
    fi

    cleanup

    echo ""
    log_info "Build Summary:"
    log_success "Successful: $successful/${#algorithms[@]}"

    if [ ${#failed[@]} -gt 0 ]; then
        log_error "Failed: ${failed[*]}"
        exit 1
    else
        log_success "All builds completed successfully!"
        log_info "Output files in: $OUTPUT_DIR"
    fi
}

case "${1:-}" in
    --help|-h)
        cat << EOF
LibOQS WASM Modular Builder

Usage: $0 [OPTIONS] [algorithm-slug]

Options:
  --help, -h         Show this help message
  --setup-only       Only clone/update LibOQS repository
  --clean            Clean build directories and LibOQS
  --list             List all available algorithm slugs
  --kem              Build all KEM algorithms only
  --sig              Build all signature algorithms only

Arguments:
  algorithm-slug     Build specific algorithm (e.g., ml-kem-768, falcon-512)

Environment Variables:
  LIBOQS_BRANCH      Branch to use (default: main)
  PARALLEL_JOBS      Number of parallel build jobs (default: 4)

Examples:
  $0                     # Build all algorithms (KEM + SIG)
  $0 --kem               # Build all KEM algorithms
  $0 --sig               # Build all signature algorithms
  $0 ml-kem-768         # Build only ML-KEM-768
  $0 --list             # Show all available algorithms
  $0 --setup-only       # Only clone/update LibOQS
  $0 --clean            # Clean all build artifacts

  # Use specific branch:
  LIBOQS_BRANCH=0.15.0 $0

  # Parallel builds with 8 jobs:
  PARALLEL_JOBS=8 $0 --sig

Note: Algorithm registry is defined in algorithms.json
EOF
        exit 0
        ;;
    --setup-only)
        setup_liboqs
        log_success "LibOQS setup completed!"
        exit 0
        ;;
    --clean)
        log_info "Cleaning build directories..."
        rm -rf "$BUILD_DIR" "$OUTPUT_DIR" "$LIBOQS_DIR"
        log_success "Clean completed"
        exit 0
        ;;
    --list)
        log_info "Available algorithms:"
        echo ""
        jq -r '
            def print_family:
                to_entries[] |
                "  \(.key): \(.value | to_entries | length) algorithms\n    \(.value | to_entries[] | .value.slug)" ;

            "KEM Algorithms:",
            (.kem | print_family),
            "",
            "Signature Algorithms:",
            (.sig | print_family),
            "",
            "Stateful Signature Algorithms:",
            (."sig-stateful" | print_family)
        ' "$ALGORITHM_REGISTRY"
        exit 0
        ;;
    *)
        main "$@"
        ;;
esac
