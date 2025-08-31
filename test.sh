#!/bin/bash

# ============================================================================
# Cloudflare Worker HMAC Token Validation Test Suite
# ============================================================================

set -euo pipefail

# Configuration
readonly DEFAULT_HOST="reflector.cloudflareapp.cc"
readonly DEFAULT_PORT=8787
readonly DEFAULT_SECRET="default-secret"
readonly TOKEN_VALIDITY_SECONDS=300

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[0;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly BOLD='\033[1m'
readonly NC='\033[0m' # No Color

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Parse command line arguments
VERBOSE=false
HOST="${HOST:-$DEFAULT_HOST}"
PORT="${PORT:-$DEFAULT_PORT}"
SECRET="${SECRET:-$DEFAULT_SECRET}"

while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -h|--host)
            HOST="$2"
            shift 2
            ;;
        -p|--port)
            PORT="$2"
            shift 2
            ;;
        -s|--secret)
            SECRET="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  -v, --verbose    Show detailed output"
            echo "  -h, --host HOST  Set host header (default: $DEFAULT_HOST)"
            echo "  -p, --port PORT  Set port (default: $DEFAULT_PORT)"
            echo "  -s, --secret KEY Set HMAC secret (default: $DEFAULT_SECRET)"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

readonly BASE_URL="http://localhost:${PORT}"

# ============================================================================
# Helper Functions
# ============================================================================

log_info() {
    echo -e "${CYAN}ℹ ${NC}$1"
}

log_success() {
    echo -e "${GREEN}✓${NC} $1"
}

log_error() {
    echo -e "${RED}✗${NC} $1"
}

log_test() {
    echo -e "\n${BLUE}▶${NC} ${BOLD}Test $((TESTS_RUN + 1)):${NC} $1"
}

# Generate HMAC token
generate_hmac_token() {
    local client_ip="${1:-127.0.0.1}"
    local timestamp="${2:-$(date +%s%3N | sed 's/...$//')}.$(date +%3N)"
    local message="${client_ip}:${timestamp}"
    local hash=$(echo -n "$message" | openssl dgst -sha256 -hmac "$SECRET" -binary | base64)
    echo "${timestamp}-${hash}"
}

# URL encode function
urlencode() {
    local string="${1}"
    local strlen=${#string}
    local encoded=""
    local pos c o

    for (( pos=0 ; pos<strlen ; pos++ )); do
        c=${string:$pos:1}
        case "$c" in
            [-_.~a-zA-Z0-9] ) o="${c}" ;;
            * ) printf -v o '%%%02x' "'$c" ;;
        esac
        encoded+="${o}"
    done
    echo "${encoded}"
}

# Run test and check status code
run_test() {
    local test_name="$1"
    local expected_code="$2"
    local url="$3"
    shift 3
    local curl_args=("$@")
    
    log_test "$test_name"
    ((TESTS_RUN++))
    
    local response
    local actual_code
    
    if [[ "$VERBOSE" == true ]]; then
        response=$(curl -s -w "\n%{http_code}" "${curl_args[@]}" "$url" 2>&1)
        actual_code=$(echo "$response" | tail -n1)
        echo -e "${CYAN}Response:${NC}"
        echo "$response" | head -n-1
    else
        actual_code=$(curl -s -o /dev/null -w "%{http_code}" "${curl_args[@]}" "$url")
    fi
    
    if [[ "$actual_code" == "$expected_code" ]]; then
        log_success "Expected $expected_code, got $actual_code"
        ((TESTS_PASSED++))
        return 0
    else
        log_error "Expected $expected_code, got $actual_code"
        ((TESTS_FAILED++))
        return 1
    fi
}

# Check if service is running
check_service() {
    log_info "Checking if service is running on port $PORT..."
    if ! nc -zv localhost "$PORT" &>/dev/null; then
        log_error "Service not running on port $PORT. Is wrangler running?"
        echo "Run: pnpm dlx wrangler dev"
        exit 1
    fi
    log_success "Service is running"
}

# ============================================================================
# Test Cases
# ============================================================================

run_all_tests() {
    local header_args=(-H "host:${HOST}")
    
    echo -e "${BOLD}${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}Running HMAC Token Validation Tests${NC}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────${NC}"
    echo -e "Host: ${HOST}, Port: ${PORT}, Secret: ${SECRET}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
    
    # Test 1: Missing function_id - should bypass
    run_test "Missing function_id (bypass)" "200" \
        "${BASE_URL}" \
        "${header_args[@]}"
    
    # Test 2: Wrong function_id - should bypass
    run_test "Non-login function_id (bypass)" "200" \
        "${BASE_URL}/?function_id=OTHER_FUNCTION" \
        "${header_args[@]}"
    
    # Test 3: Login function without oait - should fail
    run_test "Login without oait parameter" "400" \
        "${BASE_URL}/?function_id=APPS_LOGIN_DEFAULT" \
        "${header_args[@]}"
    
    # Test 4: Invalid token format - single token
    run_test "Invalid token format (single token)" "403" \
        "${BASE_URL}/?function_id=APPS_LOGIN_DEFAULT&oait=invalidtoken" \
        "${header_args[@]}"
    
    # Test 5: Invalid token format - empty oait
    run_test "Empty oait parameter" "403" \
        "${BASE_URL}/?function_id=APPS_LOGIN_DEFAULT&oait=" \
        "${header_args[@]}"
    
    # Test 6: Invalid token format - missing cloudflare token
    run_test "Missing cloudflare token" "403" \
        "${BASE_URL}/?function_id=APPS_LOGIN_DEFAULT&oait=forms_token++" \
        "${header_args[@]}"
    
    # Test 7: Invalid HMAC token
    run_test "Invalid HMAC token" "403" \
        "${BASE_URL}/?function_id=APPS_LOGIN_DEFAULT&oait=forms_token++invalid-hmac-token" \
        "${header_args[@]}"
    
    # Test 8: Expired token (old timestamp)
    local old_timestamp="1000000000.000"
    local old_message="127.0.0.1:${old_timestamp}"
    local old_hash=$(echo -n "$old_message" | openssl dgst -sha256 -hmac "$SECRET" -binary | base64)
    local expired_token="${old_timestamp}-${old_hash}"
    
    echo "Expired token: $expired_token"
    echo "url encoded: $(urlencode "$expired_token")"
    run_test "Expired HMAC token" "403" \
        "${BASE_URL}/?function_id=APPS_LOGIN_DEFAULT&oait=forms_token++$(urlencode "$expired_token")" \
        "${header_args[@]}"
    
    # Test 9: Valid token without access token
    local valid_token=$(generate_hmac_token "127.0.0.1")
    echo "Valid token: $valid_token"
    echo "url encoded: $(urlencode "$valid_token")"
    run_test "Valid token without access token" "200" \
        "${BASE_URL}/?function_id=APPS_LOGIN_DEFAULT&oait=forms_token++$(urlencode "$valid_token")" \
        "${header_args[@]}" \
        -H "CF-Connecting-IP: 127.0.0.1"
    
    # Test 10: Valid token with access token
    run_test "Valid token with access token" "200" \
        "${BASE_URL}/?function_id=APPS_LOGIN_DEFAULT&oait=forms_token++$(urlencode "$valid_token")++access_token_123" \
        "${header_args[@]}" \
        -H "CF-Connecting-IP: 127.0.0.1"
    
    # Test 11: Valid token with additional query params
    run_test "Valid token with additional params" "200" \
        "${BASE_URL}/?function_id=APPS_LOGIN_DEFAULT&foo=bar&oait=forms_token++$(urlencode "$valid_token")&baz=qux" \
        "${header_args[@]}" \
        -H "CF-Connecting-IP: 127.0.0.1"
    
    # Test 12: Valid token with X-Forwarded-For header
    local xff_token=$(generate_hmac_token "192.168.1.1")
    run_test "Valid token with X-Forwarded-For" "200" \
        "${BASE_URL}/?function_id=APPS_LOGIN_DEFAULT&oait=forms_token++$(urlencode "$xff_token")++access_token_123" \
        "${header_args[@]}" \
        -H "CF-Connecting-IP: 192.168.1.1" \
        -H "X-Forwarded-For: 192.168.1.1, 10.0.0.1"
}

# ============================================================================
# Main Execution
# ============================================================================

main() {
    check_service
    run_all_tests
    
    # Print summary
    echo -e "\n${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}Test Summary${NC}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────${NC}"
    echo -e "Total tests: ${TESTS_RUN}"
    echo -e "${GREEN}Passed: ${TESTS_PASSED}${NC}"
    echo -e "${RED}Failed: ${TESTS_FAILED}${NC}"
    
    if [[ $TESTS_FAILED -eq 0 ]]; then
        echo -e "\n${GREEN}${BOLD}All tests passed! ✨${NC}"
        exit 0
    else
        echo -e "\n${RED}${BOLD}Some tests failed ❌${NC}"
        exit 1
    fi
}

# Run main function
main
