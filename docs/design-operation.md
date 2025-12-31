# 運用設計：Pre-commit スキャンの導入検討

## 背景

### 現状
- GitHub Actions で push/PR 時にセキュリティスキャンを実行
- コミット後にしか問題を検出できない
- APIキーなどがコミットされると Git 履歴に残り、削除が困難

### 目標
- コミット前（pre-commit）の段階でリスクを検出
- チーム全員が利用可能な仕組み

---

## チーム構成の前提

| メンバータイプ | Blender環境 | 想定される作業 |
|--------------|------------|---------------|
| 3Dアーティスト | ローカルにBlenderあり | .blend ファイルの作成・編集 |
| プログラマー | Blenderなし（または未インストール） | スクリプト、CI/CD、ドキュメント |
| その他（サウンド、企画等） | Blenderなし | アセット確認、レビュー |

**要件**: Blenderの有無に関わらず、全員が安全にリポジトリを利用できること

---

## 設計案

### 全体構成

```
┌─────────────────────────────────────────────────────────────────────┐
│  セキュリティスキャンの多層防御                                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Layer 1: Pre-commit（ローカル）                                      │
│  ┌─────────────────────────┐  ┌─────────────────────────┐           │
│  │ Blenderあり環境          │  │ Blenderなし環境          │           │
│  │ → フルスキャン           │  │ → 軽量スキャン           │           │
│  │ - 全データ抽出           │  │ - Text blocks           │           │
│  │ - 完全な検出             │  │ - 文字列パターン検索     │           │
│  │ - 数秒かかる             │  │ - 高速（<1秒）           │           │
│  └─────────────────────────┘  └─────────────────────────┘           │
│              ↓                           ↓                          │
│              └───────────┬───────────────┘                          │
│                          ↓                                          │
│  Layer 2: GitHub Actions（リモート）                                  │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │ フルスキャン（最終防衛ライン）                                 │    │
│  │ - Blender使用                                                │    │
│  │ - 全データ抽出・完全な検出                                    │    │
│  │ - ERROR検出時はマージブロック                                 │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Pre-commit の動作フロー

```
git commit
    │
    ▼
┌─────────────────────────────┐
│ .blend ファイルが含まれる？   │
└─────────────────────────────┘
    │ Yes                 │ No
    ▼                     ▼
┌─────────────────┐   コミット実行
│ Blender検出     │
└─────────────────┘
    │ あり            │ なし
    ▼                 ▼
フルスキャン    ┌─────────────────────────┐
    │          │ SKIP_BLEND_SCAN=1 ?     │
    │          └─────────────────────────┘
    │              │ Yes          │ No
    │              ▼              ▼
    │          警告して許可   コミット拒否
    │              │          （Blender必要）
    ▼              ▼
┌─────────────────────────────┐
│ ERROR 検出？                 │
└─────────────────────────────┘
    │ Yes                 │ No
    ▼                     ▼
コミット拒否          コミット実行
（修正を促す）        （WARNING は表示のみ）
```

---

## 軽量スキャナーの設計（検討中）

### 目的
- Blenderなしで .blend ファイルの基本的なセキュリティチェックを行う
- 高速に実行し、開発体験を損なわない

### 技術的アプローチ

#### 方式1: blendfile ライブラリ使用
- Blender公式の Python ライブラリ
- .blend ファイルの構造を解析可能
- Text blocks の抽出が可能

```python
# 例: blendfile での Text block 抽出
from blendfile import BlendFile

with BlendFile(path) as blend:
    for block in blend.find_blocks_from_code(b'TX'):
        # Text block の内容を取得
        pass
```

#### 方式2: バイナリ直接解析
- GZIP 展開後にバイナリ検索
- 文字列パターン（APIキー、パスワード、パス）を検索
- 構造解析不要で高速

```python
import gzip
import re

def quick_scan(blend_path):
    with gzip.open(blend_path, 'rb') as f:
        content = f.read()

    # 文字列として検索可能な部分を抽出
    strings = extract_strings(content)

    # パターンマッチング
    for pattern in DANGEROUS_PATTERNS:
        if pattern.search(strings):
            yield Finding(...)
```

### 検出可能項目の比較

| 検出項目 | フルスキャン | 軽量（blendfile） | 軽量（バイナリ） |
|---------|-------------|------------------|-----------------|
| Text blocks 内容 | ○ | ○ | △（部分的） |
| APIキー・パスワード | ○ | ○ | ○ |
| 個人パス | ○ | ○ | ○ |
| Driver expressions | ○ | △ | × |
| Node scripts | ○ | × | × |
| App handlers | ○ | × | × |
| 外部参照パス | ○ | ○ | △ |

### 未解決の検討事項

1. **blendfile ライブラリの互換性**
   - Blender バージョンによる .blend 形式の差異
   - Python 3.12 との互換性確認が必要

2. **検出精度と速度のトレードオフ**
   - どこまでの検出率を許容するか
   - 軽量スキャンで見逃しがあっても CI で捕捉できる前提でよいか

3. **エラー時の挙動**
   - 軽量スキャン失敗時：コミットを許可するか拒否するか
   - Blender 検出に失敗した場合のフォールバック

4. **設定の柔軟性**
   - メンバーごとにスキャン方式を選択可能にするか
   - 環境変数やconfig ファイルでの制御

---

## 実装計画

### フェーズ1: 基盤整備 ✅ 完了

- [x] pre-commit フレームワークの導入
- [x] Blender 検出ロジックの実装
- [x] 既存スキャナーの pre-commit 対応
- [x] 設定ファイル（`.blend-scanner.yaml`）の実装
- [x] ユニットテストの追加（40件）

**実装ファイル:**
| ファイル | 説明 |
|---------|------|
| `scripts/blend_scanner/config.py` | 設定ファイル読み込み |
| `scripts/blend_scanner/blender_detector.py` | Blender検出 |
| `scripts/pre_commit_scan.py` | pre-commitエントリーポイント |
| `.blend-scanner.yaml` | プロジェクト設定 |
| `.pre-commit-config.yaml` | pre-commitフック設定 |

**決定事項:**
- Blenderバージョン: 設定ファイルで優先順位を指定

### フェーズ1.5: Blenderなし環境の安全強化 ✅ 完了

- [x] デフォルト動作を「コミット拒否」に変更
- [x] `SKIP_BLEND_SCAN=1` 環境変数で強制コミット許可
- [x] テスト追加
- [x] ドキュメント更新

**設計:**
- Blenderがない環境では、デフォルトでコミットを拒否（安全側に倒す）
- 明示的に `SKIP_BLEND_SCAN=1` を指定した場合のみ警告でコミット許可
- CIで最終的なセキュリティチェックを実施

```bash
# デフォルト: Blenderがない場合はコミット拒否
git commit -m "message"
# → ERROR: Blender not found. Install Blender or use SKIP_BLEND_SCAN=1

# 強制コミット: 環境変数でスキャンをスキップ
SKIP_BLEND_SCAN=1 git commit -m "message"
# → WARNING: Blender not found, scan skipped (CI will verify)
```

### フェーズ2: 軽量スキャナー

- [ ] blendfile ライブラリの調査・検証
- [ ] 軽量スキャナーのプロトタイプ実装
- [ ] 検出精度の評価

### フェーズ3: 統合・展開

- [x] pre-commit 設定ファイルの作成
- [ ] チーム向けセットアップ手順の文書化
- [ ] 段階的な展開とフィードバック収集

---

## 設定ファイル

### .blend-scanner.yaml

プロジェクトルートに配置するスキャナー設定ファイル。

```yaml
# Blend Scanner Configuration
blender:
  # Blender versions to use (in priority order)
  versions:
    - blender-4-LTS
    - blender-3-LTS
    - blender-5
  # Base directory containing Blender installations
  base_dir: ~/Application/blender

pre_commit:
  # Behavior when Blender is not found: error | warn | skip
  # - error: コミット拒否（デフォルト、SKIP_BLEND_SCAN=1 で上書き可能）
  # - warn: 警告のみでコミット許可
  # - skip: 何も出力せずコミット許可
  no_blender: error
  # Scanners to run
  scanners:
    - malware
    - privacy
```

### .pre-commit-config.yaml

```yaml
repos:
  - repo: local
    hooks:
      - id: scan-blend-files
        name: Scan .blend files for security issues
        entry: python scripts/pre_commit_scan.py
        language: python
        files: \.blend$
        pass_filenames: true
        additional_dependencies:
          - pyyaml>=6.0
          - bandit>=1.7.0
```

---

## セットアップ手順

```bash
# 1. 依存関係のインストール
pip install -r requirements.txt

# 2. pre-commit フックの有効化
pre-commit install

# フックが有効か確認
ls -la .git/hooks/pre-commit

# 3. 動作確認（全ファイルに対して実行）
pre-commit run --all-files
```

### Blender環境がない場合

Blenderがインストールされていない環境では、デフォルトでコミットが拒否されます。

```
[pre-commit] ERROR: Blender not found
  Install Blender or set SKIP_BLEND_SCAN=1 to skip
  CI will perform security scan on push
```

スキャンをスキップしてコミットする場合は、環境変数を設定します。

```bash
SKIP_BLEND_SCAN=1 git commit -m "message"
```

```
[pre-commit] WARNING: Blender not found, scan skipped
  CI will perform security scan on push
```

### 無効化

```bash
# pre-commit フックを無効化（.git/hooks/pre-commit を削除）
pre-commit uninstall

# 一時的にスキップしてコミット（非推奨）
git commit --no-verify -m "message"
```

---

## 更新履歴

| 日付 | 内容 |
|-----|------|
| 2024-12-31 | フェーズ1.5完了。SKIP_BLEND_SCAN環境変数を実装、デフォルト動作を「拒否」に変更 |
| 2024-12-30 | フェーズ1.5追加。Blenderなし環境のデフォルト動作を「拒否」に変更、SKIP_BLEND_SCAN環境変数を導入 |
| 2024-12-30 | フェーズ1完了。pre-commit基盤、設定ファイル、Blender検出を実装 |
| 2024-12-28 | 初版作成。pre-commit導入の検討開始 |
