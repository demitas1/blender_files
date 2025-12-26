# Blender Security Scanner マニュアル

Blenderファイル(.blend)に埋め込まれたスクリプトやデータをスキャンし、セキュリティ上の問題を検出するツールです。

## ローカルスキャン

### 前提条件

- Python 3.12以上
- Blender（`$HOME/Application/blender/` にインストール済み）

### 基本的な使い方

```bash
# 基本スキャン
python3 scripts/scan_blend.py <blend_file>

# 例
python3 scripts/scan_blend.py assets/meshes/robot/robot.blend
```

### オプション

```bash
# 詳細出力（抽出されたスクリプト内容を表示）
python3 scripts/scan_blend.py <blend_file> --verbose

# Blenderバージョンを指定
python3 scripts/scan_blend.py <blend_file> -b blender-4-LTS

# 利用可能なBlenderバージョン一覧
python3 scripts/scan_blend.py --list-versions

# 特定のスキャナーのみ実行
python3 scripts/scan_blend.py <blend_file> --scanners malware
python3 scripts/scan_blend.py <blend_file> --scanners privacy
python3 scripts/scan_blend.py <blend_file> --scanners malware,privacy
```

### 出力の見方

```
============================================================
Blender Security Scanner
============================================================

[Extracted Data]
  Text blocks: 3
    - script1.py
    - script2.py
    - rig_ui.py
  Driver expressions: 0
  External references: 2

[ERROR] 1 dangerous pattern(s) detected!

  [malware] script1.py:15
    os.system: Shell command execution
    os.system("rm -rf /")

[WARNING] 2 pattern(s) requiring review

  [malware] rig_ui.py:1038
    eval(): Dynamic expression evaluation (may be legitimate in Rigify)
    return eval(names_string)

  [privacy] script2.py:5
    Linux user home path detected
    path = "/home/username/projects/"

============================================================
Scan complete: 1 error(s), 2 warning(s)
```

- **ERROR**: 危険なパターン。対応が必要
- **WARNING**: 確認が必要なパターン。正当な使用の場合もある
- **INFO**: 参考情報（`--verbose`時のみ表示）

### 終了コード

| コード | 意味 |
|--------|------|
| 0 | 問題なし、またはWARNINGのみ |
| 1 | ERRORレベルの問題を検出 |

## GitHub Actions

### 自動実行

以下の条件で自動的にスキャンが実行されます：

- `assets/**/*.blend` へのpush
- `assets/**/*.blend` を変更するPull Request

### 手動実行

#### GitHub CLI (gh) を使用

```bash
# 現在のブランチで実行
gh workflow run "Scan Blend Files"

# ブランチを指定して実行
gh workflow run "Scan Blend Files" --ref <branch_name>

# 例
gh workflow run "Scan Blend Files" --ref work/test-github-action
gh workflow run "Scan Blend Files" --ref main
```

#### 実行状態の確認

```bash
# 最近の実行一覧
gh run list --workflow="Scan Blend Files" --limit 5

# 特定のブランチの実行一覧
gh run list --workflow="Scan Blend Files" --branch main --limit 5

# 実行詳細を表示
gh run view <run_id>

# 失敗したログを表示
gh run view <run_id> --log-failed

# 全ログを表示
gh run view <run_id> --log
```

#### 実行中のワークフローを監視

```bash
# 実行完了まで待機
gh run watch <run_id>

# 最新の実行を監視
gh run list --workflow="Scan Blend Files" --limit 1 --json databaseId -q '.[0].databaseId' | xargs gh run watch
```

### GitHub Web UI から手動実行

1. リポジトリの「Actions」タブを開く
2. 左サイドバーから「Scan Blend Files」を選択
3. 「Run workflow」ボタンをクリック
4. ブランチを選択して「Run workflow」を実行

## トラブルシューティング

### Blenderが見つからない

```
Error: Blender not found: /home/user/Application/blender/blender-5
```

**解決方法**:
```bash
# 利用可能なバージョンを確認
python3 scripts/scan_blend.py --list-versions

# 存在するバージョンを指定
python3 scripts/scan_blend.py <blend_file> -b blender-4-LTS
```

### LFSファイルが取得できない

GitHub Actionsでblendファイルがスキャンできない場合、LFSが正しく設定されているか確認：

```bash
# LFSの状態確認
git lfs status

# LFSファイルを取得
git lfs pull
```

### banditが見つからない

```
Note: bandit is not installed
Install: pip install bandit
```

**解決方法**:
```bash
pip install bandit
```
