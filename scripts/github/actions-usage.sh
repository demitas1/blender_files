#!/bin/bash
set -euo pipefail

# 色定義
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

error() {
    echo -e "${RED}Error: $1${NC}" >&2
    exit 1
}

info() {
    echo -e "${GREEN}$1${NC}"
}

warn() {
    echo -e "${YELLOW}$1${NC}"
}

# gh CLIがインストールされているか確認
command -v gh &> /dev/null || error "gh CLI is not installed"

# 認証状態を確認してユーザー名を取得
OWNER=$(gh api user --jq '.login' 2>/dev/null) || error "Not authenticated. Run 'gh auth login' first"

# カレントディレクトリがgitリポジトリか確認
git rev-parse --is-inside-work-tree &> /dev/null || error "Not a git repository"

# リモートURLからリポジトリ名を取得
REMOTE_URL=$(git remote get-url origin 2>/dev/null) || error "No 'origin' remote found"

# URLからリポジトリ名を抽出 (HTTPS/SSH両対応)
if [[ "$REMOTE_URL" =~ github\.com[:/]([^/]+)/([^/.]+)(\.git)?$ ]]; then
    REPO_OWNER="${BASH_REMATCH[1]}"
    REPO_NAME="${BASH_REMATCH[2]}"
else
    error "Could not parse GitHub repository from remote URL: $REMOTE_URL"
fi

FULL_REPO="$REPO_OWNER/$REPO_NAME"

# 引数から年月を取得、省略時は現在の年月
if [[ $# -ge 2 ]]; then
    YEAR="$1"
    MONTH=$(printf "%02d" "$2")
elif [[ $# -eq 1 ]]; then
    error "Usage: $0 [YEAR MONTH]\n  Example: $0 2024 12"
else
    YEAR=$(date +%Y)
    MONTH=$(date +%m)
fi

# 年月のバリデーション
[[ "$YEAR" =~ ^[0-9]{4}$ ]] || error "Invalid year: $YEAR"
[[ "$MONTH" =~ ^(0[1-9]|1[0-2])$ ]] || error "Invalid month: $MONTH"

# 月の最初と最後の日を計算
START="${YEAR}-${MONTH}-01"
# 翌月の1日の前日 = 当月の最終日
if [[ "$MONTH" == "12" ]]; then
    END="${YEAR}-12-31"
else
    NEXT_MONTH=$(printf "%02d" $((10#$MONTH + 1)))
    END=$(date -d "${YEAR}-${NEXT_MONTH}-01 -1 day" +%Y-%m-%d 2>/dev/null) || \
        END=$(date -v-1d -j -f "%Y-%m-%d" "${YEAR}-${NEXT_MONTH}-01" +%Y-%m-%d 2>/dev/null) || \
        error "Failed to calculate end date"
fi

echo "========================================"
info "GitHub Actions Monthly Usage Report"
echo "========================================"
echo "User:       $OWNER"
echo "Repository: $FULL_REPO"
echo "Period:     $START to $END"
echo "========================================"
echo ""

# ワークフロー実行一覧を取得
info "Fetching workflow runs..."

RUN_IDS=$(gh run list -R "$FULL_REPO" --created "${START}..${END}" -L 500 --json databaseId -q '.[].databaseId' 2>/dev/null) || \
    error "Failed to fetch workflow runs. Check repository access."

if [[ -z "$RUN_IDS" ]]; then
    warn "No workflow runs found for this period."
    exit 0
fi

RUN_COUNT=$(echo "$RUN_IDS" | wc -l | tr -d ' ')
info "Found $RUN_COUNT workflow runs"
echo ""

# 各OSごとの合計時間を集計
declare -A total_ms
total_ms[UBUNTU]=0
total_ms[MACOS]=0
total_ms[WINDOWS]=0

# 実行時間（run_duration_ms）の合計
total_run_duration_ms=0

current=0
for id in $RUN_IDS; do
    ((++current))
    printf "\rProcessing: %d/%d" "$current" "$RUN_COUNT"
    
    timing=$(gh api "/repos/$FULL_REPO/actions/runs/$id/timing" 2>/dev/null) || continue
    
    for os in UBUNTU MACOS WINDOWS; do
        ms=$(echo "$timing" | jq -r ".billable.${os}.total_ms // 0")
        total_ms[$os]=$((${total_ms[$os]} + ms))
    done

    # run_duration_ms を集計
    run_ms=$(echo "$timing" | jq -r ".run_duration_ms // 0")
    total_run_duration_ms=$((total_run_duration_ms + run_ms))
    
    # レート制限対策
    sleep 0.1
done

echo ""
echo ""

# 実行時間の表示
run_duration_sec=$((total_run_duration_ms / 1000))
run_duration_min=$((run_duration_sec / 60))
run_duration_sec_remainder=$((run_duration_sec % 60))

echo "========================================"
info "Run Duration (実行時間)"
echo "========================================"
printf "Total: %d min %d sec (%d ms)\n" "$run_duration_min" "$run_duration_sec_remainder" "$total_run_duration_ms"
echo ""

echo "========================================"
info "Results (Billable Minutes)"
echo "========================================"

# 分に変換して表示
linux_min=$((${total_ms[UBUNTU]} / 60000))
macos_min=$((${total_ms[MACOS]} / 60000))
windows_min=$((${total_ms[WINDOWS]} / 60000))

# 換算後の分数（Free planの消費分として）
linux_weighted=$linux_min
macos_weighted=$((macos_min * 10))
windows_weighted=$((windows_min * 2))
total_weighted=$((linux_weighted + macos_weighted + windows_weighted))

printf "%-12s %8d min\n" "Linux:" "$linux_min"
printf "%-12s %8d min (x10 = %d)\n" "macOS:" "$macos_min" "$macos_weighted"
printf "%-12s %8d min (x2  = %d)\n" "Windows:" "$windows_min" "$windows_weighted"
echo "----------------------------------------"
printf "%-12s %8d min (weighted)\n" "Total:" "$total_weighted"
echo ""

# Free plan (2000分) との比較
FREE_QUOTA=2000
remaining=$((FREE_QUOTA - total_weighted))
usage_percent=$((total_weighted * 100 / FREE_QUOTA))

if [[ $remaining -ge 0 ]]; then
    info "Free plan usage: ${usage_percent}% ($total_weighted / $FREE_QUOTA min)"
    echo "Remaining: $remaining min"
else
    warn "⚠️  Exceeded free quota by $((remaining * -1)) min!"
fi
