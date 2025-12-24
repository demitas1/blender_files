# Blender関連ファイルの管理用リポジトリ

## Blenderファイルの検査手法

### 1. Blenderのバックグラウンドモードで抽出・検査

Blenderにはヘッドレス実行モードがあり、Pythonスクリプトでファイル内のテキストブロックやドライバーを抽出できます。

```bash
blender --background yourfile.blend --python extract_scripts.py
```

抽出用スクリプトの例：

```python
import bpy
import sys

# テキストブロック（埋め込みスクリプト）
for text in bpy.data.texts:
    print(f"=== Text: {text.name} ===")
    print(text.as_string())

# ドライバー内のPython式
for obj in bpy.data.objects:
    if obj.animation_data:
        for driver in obj.animation_data.drivers:
            print(f"Driver expression: {driver.driver.expression}")

# ハンドラー登録の有無は実行時にしかわからないが、
# テキストブロック内で app.handlers を検索することは可能
```

### 2. 抽出後の静的解析

抽出したコードに対して既存ツールを適用できます：

- **bandit** - Python用セキュリティリンター（`os.system`, `subprocess`, `eval`などを検出）
- **semgrep** - カスタムルールで危険パターンを検出
- **単純なgrep** - `import os`, `subprocess`, `socket`, `requests`などの検索

### 3. GitHub Actionsの構成例

```yaml
- name: Extract and scan scripts
  run: |
    blender --background ${{ matrix.blend_file }} --python .github/scripts/extract.py > scripts.txt
    bandit -r scripts.txt || true
    grep -E "(os\.system|subprocess|eval|exec|socket)" scripts.txt && exit 1 || true
```

### 3. Blenderのgithub actinosインストール

公式Dockerイメージを使用する

```
jobs:
  scan-blend:
    runs-on: ubuntu-latest
    container:
      image: docker.io/blender/blender:4.2
    steps:
      - uses: actions/checkout@v4
      - name: Extract scripts
        run: |
          blender --background myfile.blend --python extract.py
```

## 注意点

- **.blendは圧縮されたバイナリ**なので、直接パースするよりBlender経由が確実
- **ノードのスクリプトノード**や**Geometry Nodesのスクリプト**も確認対象に含めるべき
- 完全な検出は難しいので、既知の危険パターンのブラックリスト方式が現実的


## ローカル実行環境について

- Ubuntu 24 LTS
- X11 desktop
- Blender実行ファイル
    - `$HOME/Application/blender/` に複数のバージョンを格納
    blender-3-LTS -> blender-3.6.20-linux-x64/blender-3.6.20-linux-x64/blender
    blender-4 -> blender-4.4.3-linux-x64/blender
    blender-4-LTS -> blender-4.5.0-linux-x64/blender
    blender-5 -> blender-5.0.0-linux-x64/blender

    - スクリプトで環境設定ファイルを読み取り実行ファイルを指定できるようにする

## ディレクトリ構成

```

robot-parts/                          # または game-assets/ など
├── README.md
├── LICENSE
├── CONTRIBUTING.md
│
├── .github/
│   ├── workflows/
│   │   ├── scan-scripts.yml          # スクリプト安全性検査
│   │   ├── validate-blend.yml        # blendファイルの整合性チェック
│   │   └── export-check.yml          # エクスポート可能性の確認
│   └── scripts/
│       ├── extract_scripts.py        # スクリプト抽出
│       ├── validate_blend.py         # 構造検証
│       └── dangerous_patterns.txt    # 検出パターン定義
│
├── assets/
│   ├── meshes/                       # 再利用可能な単体メッシュ
│   │   ├── actuators/
│   │   │   ├── servo_motor.blend
│   │   │   ├── servo_motor.gltf
│   │   │   └── README.md             # 使用方法・ライセンス
│   │   ├── joints/
│   │   ├── frames/
│   │   └── sensors/
│   │
│   ├── scenes/                       # 完成シーン・デモ
│   │   ├── robot_arm_demo/
│   │   └── mobile_robot_demo/
│   │
│   ├── animations/                   # リグ付きアニメーション
│   │
│   ├── node-groups/                  # 再利用可能なノード
│   │   ├── geometry/                 # ジオメトリノード
│   │   └── shaders/                  # シェーダーノード
│   │
│   └── materials/                    # マテリアルライブラリ
│
├── templates/                        # 新規アセット作成用テンプレート
│
├── docs/
│   └── images/
│
└── scripts/                          # ローカル開発用スクリプト
```
