# Blender Security Scanner 設計ドキュメント

## 概要

Blenderファイル(.blend)のセキュリティスキャンを行うモジュール化されたツール。
マルウェア検出と個人情報・シークレット検出の2つの主要機能を提供する。

## アーキテクチャ

```
scripts/
├── blend_scanner/              # メインパッケージ
│   ├── __init__.py
│   ├── cli.py                  # CLIエントリーポイント
│   ├── core.py                 # スキャナー統合・オーケストレーション
│   ├── models.py               # データクラス定義
│   ├── colors.py               # 出力カラー定義
│   │
│   ├── extractors/             # Blenderからのデータ抽出
│   │   ├── __init__.py
│   │   ├── base.py             # 抽出器基底クラス
│   │   ├── text_blocks.py      # テキストブロック抽出
│   │   ├── drivers.py          # ドライバー式抽出
│   │   ├── nodes.py            # ノードスクリプト抽出
│   │   ├── metadata.py         # メタデータ抽出
│   │   └── external_refs.py    # 外部参照パス抽出
│   │
│   └── scanners/               # セキュリティスキャナー
│       ├── __init__.py
│       ├── base.py             # スキャナー基底クラス
│       ├── malware.py          # マルウェアパターン検出
│       ├── privacy.py          # 個人情報・シークレット検出
│       └── bandit.py           # bandit連携
│
├── blender/                    # Blender内実行スクリプト
│   └── extract_all.py          # 統合抽出スクリプト
│
└── scan_blend.py               # CLIエントリーポイント
```

## モジュール責任範囲

### extractors/ - データ抽出層

Blenderファイルからデータを抽出する責任を持つ。

| モジュール | 責任 |
|-----------|------|
| `text_blocks.py` | 埋め込みテキストブロック（Pythonスクリプト等）の抽出 |
| `drivers.py` | ドライバー内のPython式の抽出 |
| `nodes.py` | Geometry Nodes等のスクリプトノード抽出 |
| `metadata.py` | ファイルパス、作成者情報等のメタデータ抽出 |
| `external_refs.py` | テクスチャ、リンクライブラリ等の外部参照パス抽出 |

### scanners/ - セキュリティスキャン層

抽出されたデータに対してセキュリティスキャンを実行する責任を持つ。

| モジュール | 責任 |
|-----------|------|
| `malware.py` | 危険なコードパターン検出（os.system, subprocess等） |
| `privacy.py` | 個人情報・シークレット検出（ユーザー名、APIキー等） |
| `bandit.py` | banditツールとの連携 |

### core.py - オーケストレーション層

抽出器とスキャナーの組み合わせ、結果の集約を担当。

## データモデル

### Severity（深刻度）

```python
class Severity(Enum):
    ERROR = "error"      # 危険：即座に対応必要
    WARNING = "warning"  # 警告：確認推奨
    INFO = "info"        # 情報：参考
```

### Finding（検出結果）

```python
@dataclass
class Finding:
    scanner: str         # スキャナー名
    severity: Severity   # 深刻度
    message: str         # 説明メッセージ
    location: str        # ファイル/ブロック名:行番号
    matched_text: str    # マッチしたテキスト
```

### ExtractedData（抽出データ）

```python
@dataclass
class ExtractedData:
    text_blocks: dict[str, str]      # {name: content}
    driver_expressions: list[str]     # ドライバー式
    node_scripts: list[str]           # ノードスクリプト
    metadata: dict[str, str]          # メタデータ
    external_refs: list[str]          # 外部参照パス
```

## 検出パターン

### malware.py - マルウェア検出

**ERROR レベル（危険）**:
- `os.system`, `os.popen` - シェルコマンド実行
- `subprocess` - プロセス生成
- `exec(` - 動的コード実行
- `socket.` - ネットワーク接続
- `requests.`, `urllib.` - HTTP通信
- `shutil.rmtree` - ディレクトリ削除
- `__import__` - 動的インポート

**WARNING レベル（要確認）**:
- `eval(` - 動的式評価（Rigify等で正当利用あり）

### privacy.py - 個人情報・シークレット検出

**ERROR レベル（高リスク）**:
- APIキー: `sk-[a-zA-Z0-9]{20,}`, `ghp_[a-zA-Z0-9]{36}`, `AKIA[0-9A-Z]{16}`
- パスワード変数: `(password|passwd|pwd)\s*=\s*["'][^"']+["']`
- 接続文字列: `(mysql|postgres|mongodb)://[^\s]+`
- プライベートキー: `-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----`

**WARNING レベル（要確認）**:
- Linuxユーザーパス: `/home/[a-zA-Z][a-zA-Z0-9_-]+/`
- Windowsユーザーパス: `C:\\Users\\[^\\]+\\`
- メールアドレス: `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`
- IPアドレス（プライベート除く）
- 汎用トークン: `(token|api_key|secret)\s*=\s*["'][^"']+["']`

**INFO レベル（参考情報）**:
- 絶対パス検出

## 使用方法

```bash
# 基本スキャン
python scripts/scan_blend.py <blend_file>

# 詳細出力
python scripts/scan_blend.py <blend_file> --verbose

# 特定スキャナーのみ実行
python scripts/scan_blend.py <blend_file> --scanners malware,privacy

# Blenderバージョン指定
python scripts/scan_blend.py <blend_file> -b blender-4-LTS
```

## 拡張性

新しいスキャナーを追加するには:

1. `scanners/` に新しいモジュールを作成
2. `BaseScanner` を継承
3. `name` プロパティと `scan()` メソッドを実装
4. `scanners/__init__.py` で登録

```python
from blend_scanner.scanners.base import BaseScanner, Finding, Severity

class MyScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "my_scanner"

    def scan(self, content: str, source: str) -> list[Finding]:
        findings = []
        # スキャンロジック
        return findings
```
