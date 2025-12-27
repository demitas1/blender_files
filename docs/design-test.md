# blend_scanner テスト設計

このドキュメントでは `blend_scanner` モジュールのテスト構成について説明します。

## 概要

テストは pytest を使用して実装されており、以下の2種類に分類されます：

1. **ユニットテスト**: 各コンポーネントを個別にテスト（モック使用）
2. **統合テスト**: 実際の `.blend` ファイルを使用したエンドツーエンドテスト

## ディレクトリ構造

```
scripts/tests/
├── conftest.py                  # pytest フィクスチャ定義
├── fixtures/                    # テスト用 .blend ファイル
│   ├── external/
│   │   └── texture.png          # 外部参照用ダミー画像
│   ├── clean.blend              # クリーンなファイル
│   ├── with_safe_script.blend   # 安全なスクリプト
│   ├── with_malware_patterns.blend  # マルウェアパターン
│   ├── with_privacy_issues.blend    # プライバシー問題
│   ├── with_drivers.blend       # ドライバー式
│   └── with_external_refs.blend # 外部参照
├── test_models.py               # データモデルのテスト
├── test_malware_scanner.py      # MalwareScanner のテスト
├── test_privacy_scanner.py      # PrivacyScanner のテスト
├── test_bandit_scanner.py       # BanditScanner のテスト
├── test_core.py                 # BlendScanner core のテスト
└── test_integration.py          # 統合テスト
```

## テスト実行方法

```bash
# venv を有効化
source venv/bin/activate

# 全テスト実行
pytest scripts/tests/ -v

# 特定のテストファイルのみ
pytest scripts/tests/test_integration.py -v

# 特定のテストクラスのみ
pytest scripts/tests/test_integration.py::TestMalwarePatternsBlendFile -v

# カバレッジ付き（pytest-cov が必要）
pytest scripts/tests/ --cov=scripts/blend_scanner --cov-report=html
```

## ユニットテスト

### test_models.py

データモデル（`models.py`）のテスト。

| クラス | テスト内容 |
|-------|-----------|
| `TestSeverity` | Severity enum の値と比較 |
| `TestFinding` | Finding dataclass の生成と等価性 |
| `TestExtractedData` | デフォルト値と値の設定 |
| `TestScanResult` | `has_errors`, `has_warnings`, フィルタリングメソッド |

### test_malware_scanner.py

マルウェアスキャナー（`scanners/malware.py`）のテスト。

| クラス | テスト内容 |
|-------|-----------|
| `TestMalwareScannerProperties` | `name`, `description` プロパティ |
| `TestMalwareScannerDangerousPatterns` | ERROR レベルパターン検出（os.system, subprocess 等） |
| `TestMalwareScannerWarningPatterns` | WARNING レベルパターン検出（eval） |
| `TestMalwareScannerSafeCode` | 安全なコードは検出されない |
| `TestMalwareScannerMultiline` | 複数行コードと行番号 |
| `TestMalwareScannerScanMultiple` | 複数コンテンツのスキャン |

### test_privacy_scanner.py

プライバシースキャナー（`scanners/privacy.py`）のテスト。

| クラス | テスト内容 |
|-------|-----------|
| `TestPrivacyScannerProperties` | `name`, `description` プロパティ |
| `TestPrivacyScannerErrorPatterns` | APIキー、パスワード、接続文字列、秘密鍵の検出 |
| `TestPrivacyScannerWarningPatterns` | ユーザーパス、メール、トークン変数の検出 |
| `TestPrivacyScannerInfoPatterns` | パブリックIPアドレスの検出 |
| `TestPrivacyScannerSafeCode` | 安全なコードは検出されない |
| `TestPrivacyScannerMasking` | 機密データのマスキング |

### test_bandit_scanner.py

Bandit 統合スキャナー（`scanners/bandit.py`）のテスト。

| クラス | テスト内容 |
|-------|-----------|
| `TestBanditScannerProperties` | `name`, `description` プロパティ |
| `TestBanditScannerAvailability` | `is_available()` メソッド |
| `TestBanditScannerSeverityMapping` | Bandit → 内部 Severity マッピング |
| `TestBanditScannerParsing` | JSON 出力のパース |
| `TestBanditScannerScanMultiple` | 複数ファイルスキャン（モック使用） |
| `TestBanditScannerIntegration` | 実際の bandit 実行（bandit が利用可能な場合） |

### test_core.py

コアモジュール（`core.py`）のテスト。

| クラス | テスト内容 |
|-------|-----------|
| `TestBlendScannerInit` | 初期化、デフォルトスキャナー、カスタムスキャナー |
| `TestBlendScannerGetBlenderPath` | Blender パス解決 |
| `TestBlendScannerListVersions` | バージョン一覧取得 |
| `TestBlendScannerParseOutput` | Blender 出力のパース |
| `TestBlendScannerRunScanners` | スキャナー実行 |
| `TestBlendScannerScan` | `scan()` メソッド |
| `TestBlendScannerExtractData` | `_extract_data()` メソッド |

## 統合テスト

### test_integration.py

実際の `.blend` ファイルを使用したテスト。Blender 3.6 LTS が必要です。

#### テスト用 .blend ファイル

| ファイル | 目的 | 検証内容 |
|---------|------|---------|
| `clean.blend` | クリーンなファイル | スクリプトなし、問題なし |
| `with_safe_script.blend` | 安全なスクリプト | ERROR が検出されないこと |
| `with_malware_patterns.blend` | マルウェアパターン | 危険なコードが検出されること |
| `with_privacy_issues.blend` | プライバシー問題 | APIキー、パスワード等が検出されること |
| `with_drivers.blend` | ドライバー式 | ドライバー式が抽出されること |
| `with_external_refs.blend` | 外部参照 | 外部参照パスが抽出されること |

#### テストクラス

| クラス | テスト数 | 説明 |
|-------|---------|------|
| `TestCleanBlendFile` | 2 | クリーンファイルにはテキストブロックも問題もない |
| `TestSafeScriptBlendFile` | 2 | 安全なスクリプトは malware/privacy エラーを出さない |
| `TestMalwarePatternsBlendFile` | 6 | os.system, subprocess, exec, eval を検出 |
| `TestPrivacyIssuesBlendFile` | 9 | OpenAI キー、GitHub トークン、パスワード等を検出 |
| `TestDriversBlendFile` | 2 | ドライバー式の抽出を確認 |
| `TestExternalRefsBlendFile` | 2 | 外部参照の抽出を確認 |
| `TestMetadataExtraction` | 2 | メタデータの抽出を確認 |
| `TestScanResultProperties` | 5 | ScanResult のプロパティとメソッドを検証 |
| `TestBanditIntegration` | 2 | Bandit 統合が正しく動作することを確認 |

### ドライバー式テストの目的

Blender のドライバーは任意の Python 式を実行できるため、セキュリティリスクがあります：

```python
# 安全なドライバー式
frame * 0.1
sin(frame / 10)

# 危険なドライバー式（理論上可能）
__import__('os').system('rm -rf /')
```

`with_drivers.blend` テストは、ドライバー式が正しく抽出され、スキャナーで検査できることを確認します。

### 外部参照テストの目的

外部参照パスにはユーザー名などの個人情報が含まれる可能性があります：

```
/home/username/textures/image.png    # ユーザー名漏洩
C:\Users\john\Documents\model.blend  # 同上
```

`with_external_refs.blend` テストは、外部参照が正しく抽出され、`PrivacyScanner` でパスに含まれる個人情報を検出できることを確認します。

## フィクスチャ

### conftest.py で定義されるフィクスチャ

#### スキャナーインスタンス

```python
@pytest.fixture
def malware_scanner():
    return MalwareScanner()

@pytest.fixture
def privacy_scanner():
    return PrivacyScanner()

@pytest.fixture
def bandit_scanner():
    return BanditScanner()
```

#### サンプルデータ

```python
@pytest.fixture
def sample_extracted_data():
    """テスト用の ExtractedData"""

@pytest.fixture
def malicious_code():
    """マルウェアパターンを含むコード"""

@pytest.fixture
def privacy_leak_code():
    """プライバシー問題を含むコード"""

@pytest.fixture
def safe_code():
    """安全なコード"""
```

#### .blend ファイルパス

```python
@pytest.fixture
def clean_blend():
    return FIXTURES_DIR / "clean.blend"

@pytest.fixture
def with_malware_patterns_blend():
    return FIXTURES_DIR / "with_malware_patterns.blend"

# ... 他のファイルも同様
```

#### BlendScanner インスタンス

```python
@pytest.fixture
def blend_scanner_36():
    """Blender 3.6 LTS 用の BlendScanner"""
    try:
        return BlendScanner(blender_version="blender-3-LTS")
    except FileNotFoundError:
        pytest.skip("Blender 3.6 LTS not available")
```

## テスト用 .blend ファイルの作成方法

### clean.blend

1. Blender を起動
2. デフォルトの Cube をそのまま残す
3. `File > Save As > tests/fixtures/clean.blend`

### with_safe_script.blend

1. Blender を起動
2. Scripting ワークスペースに切り替え
3. `Text > New` でテキストブロック作成（名前: `safe_script.py`）
4. 安全なコードを入力（math, print 等）
5. 保存

### with_malware_patterns.blend

1. Blender を起動
2. テキストブロック作成（名前: `malicious_script.py`）
3. 以下のパターンを含むコードを入力：
   - `os.system()`
   - `subprocess.call()`
   - `exec()`
   - `eval()`
4. 保存

### with_privacy_issues.blend

1. Blender を起動
2. テキストブロック作成（名前: `config.py`）
3. 以下を含むコードを入力：
   - ダミー API キー（`sk-...`, `ghp_...`）
   - パスワード変数
   - データベース接続文字列
   - メールアドレス
   - ユーザーパス
4. 保存

### with_drivers.blend

1. Blender を起動
2. Cube を選択
3. `Location X` を右クリック → `Add Driver`
4. Expression に `frame * 0.1` を設定
5. 保存

### with_external_refs.blend

1. 外部画像を用意（`tests/fixtures/external/texture.png`）
2. Blender を起動
3. マテリアルに Image Texture ノードを追加
4. 外部画像を選択（パックしない）
5. 保存

## CI での実行

GitHub Actions で統合テストを実行する場合は、Blender のインストールが必要です：

```yaml
- name: Install Blender
  run: |
    # Blender をダウンロード・インストール

- name: Run tests
  run: |
    source venv/bin/activate
    pytest scripts/tests/ -v
```

統合テストは Blender が利用できない環境では自動的にスキップされます。
