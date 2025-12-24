"""
Blenderファイルから埋め込みスクリプトとドライバー式を抽出するスクリプト
使用方法: blender --background yourfile.blend --python extract_scripts.py
"""
import bpy


def extract_text_blocks():
    """テキストブロック（埋め込みスクリプト）を抽出"""
    for text in bpy.data.texts:
        print(f"=== Text Block: {text.name} ===")
        print(text.as_string())
        print()


def extract_driver_expressions():
    """ドライバー内のPython式を抽出"""
    drivers_found = False

    for obj in bpy.data.objects:
        if obj.animation_data and obj.animation_data.drivers:
            for driver in obj.animation_data.drivers:
                if not drivers_found:
                    print("=== Driver Expressions ===")
                    drivers_found = True
                print(f"Object: {obj.name}, Path: {driver.data_path}")
                print(f"  Expression: {driver.driver.expression}")

    # シェイプキーのドライバーもチェック
    for key in bpy.data.shape_keys:
        if key.animation_data and key.animation_data.drivers:
            for driver in key.animation_data.drivers:
                if not drivers_found:
                    print("=== Driver Expressions ===")
                    drivers_found = True
                print(f"ShapeKey: {key.name}, Path: {driver.data_path}")
                print(f"  Expression: {driver.driver.expression}")


def extract_node_scripts():
    """ノード内のスクリプトを抽出（Geometry Nodes等）"""
    scripts_found = False

    for node_group in bpy.data.node_groups:
        for node in node_group.nodes:
            # Script nodeのチェック
            if hasattr(node, 'script') and node.script:
                if not scripts_found:
                    print("=== Node Scripts ===")
                    scripts_found = True
                print(f"NodeGroup: {node_group.name}, Node: {node.name}")
                print(f"  Script: {node.script.name}")


def main():
    print("=" * 60)
    print("Blender Script Extraction Report")
    print(f"File: {bpy.data.filepath}")
    print("=" * 60)
    print()

    extract_text_blocks()
    extract_driver_expressions()
    extract_node_scripts()

    print("=" * 60)
    print("Extraction Complete")
    print("=" * 60)


if __name__ == "__main__":
    main()
