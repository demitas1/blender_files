# GitHub Utilities

GitHub関連のユーティリティスクリプト集。

## actions-usage.sh

GitHub Actionsの月間使用量をレポートするスクリプト。

### 依存関係

- `gh` CLI（認証済み）
- `jq`

### 使い方

```bash
# カレントディレクトリのリポジトリで現在月の使用量を表示
./scripts/github/actions-usage.sh

# 特定の年月を指定
./scripts/github/actions-usage.sh 2025 12
```

### 出力内容

- **Run Duration**: 実際のワークフロー実行時間の合計
- **Billable Minutes**: 課金対象時間（OS別、重み付け換算）
  - Linux: x1
  - macOS: x10
  - Windows: x2
- **Free plan usage**: 無料枠（2000分）に対する使用率
