"""
Extract all security-relevant data from Blender files.

Usage: blender --background yourfile.blend --python extract_all.py

This script is executed within Blender's Python environment and uses
the bpy module to access Blender data.
"""

import bpy


def extract_text_blocks():
    """Extract text blocks (embedded scripts)."""
    for text in bpy.data.texts:
        print(f"=== Text Block: {text.name} ===")
        print(text.as_string())
        print()


def extract_driver_expressions():
    """Extract Python expressions from drivers."""
    drivers_found = False

    # Check object drivers
    for obj in bpy.data.objects:
        if obj.animation_data and obj.animation_data.drivers:
            for driver in obj.animation_data.drivers:
                if not drivers_found:
                    print("=== Driver Expressions ===")
                    drivers_found = True
                print(f"Object: {obj.name}, Path: {driver.data_path}")
                print(f"  Expression: {driver.driver.expression}")

    # Check shape key drivers
    for key in bpy.data.shape_keys:
        if key.animation_data and key.animation_data.drivers:
            for driver in key.animation_data.drivers:
                if not drivers_found:
                    print("=== Driver Expressions ===")
                    drivers_found = True
                print(f"ShapeKey: {key.name}, Path: {driver.data_path}")
                print(f"  Expression: {driver.driver.expression}")

    # Check material drivers
    for mat in bpy.data.materials:
        if mat.animation_data and mat.animation_data.drivers:
            for driver in mat.animation_data.drivers:
                if not drivers_found:
                    print("=== Driver Expressions ===")
                    drivers_found = True
                print(f"Material: {mat.name}, Path: {driver.data_path}")
                print(f"  Expression: {driver.driver.expression}")

    if drivers_found:
        print()


def extract_node_scripts():
    """Extract scripts from nodes (Geometry Nodes, etc.)."""
    scripts_found = False

    for node_group in bpy.data.node_groups:
        for node in node_group.nodes:
            # Check Script nodes
            if hasattr(node, "script") and node.script:
                if not scripts_found:
                    print("=== Node Scripts ===")
                    scripts_found = True
                print(f"NodeGroup: {node_group.name}, Node: {node.name}")
                print(f"  Script: {node.script.name}")

    if scripts_found:
        print()


def extract_metadata():
    """Extract file metadata."""
    print("=== Metadata ===")
    print(f"filepath: {bpy.data.filepath}")
    print(f"version: {bpy.app.version_string}")

    # Scene metadata
    for scene in bpy.data.scenes:
        if scene.render.use_stamp_note:
            print(f"scene_note ({scene.name}): {scene.render.stamp_note_text}")

    print()


def extract_external_refs():
    """Extract external reference paths (textures, linked libraries, etc.)."""
    refs_found = False

    # Linked libraries
    for lib in bpy.data.libraries:
        if not refs_found:
            print("=== External References ===")
            refs_found = True
        print(f"library: {lib.filepath}")

    # Image paths
    for img in bpy.data.images:
        if img.filepath:
            if not refs_found:
                print("=== External References ===")
                refs_found = True
            print(f"image: {img.filepath}")

    # Sound paths
    for sound in bpy.data.sounds:
        if sound.filepath:
            if not refs_found:
                print("=== External References ===")
                refs_found = True
            print(f"sound: {sound.filepath}")

    # Movie clip paths
    for clip in bpy.data.movieclips:
        if clip.filepath:
            if not refs_found:
                print("=== External References ===")
                refs_found = True
            print(f"movieclip: {clip.filepath}")

    # Font paths
    for font in bpy.data.fonts:
        if font.filepath and font.filepath != "<builtin>":
            if not refs_found:
                print("=== External References ===")
                refs_found = True
            print(f"font: {font.filepath}")

    # Cache file paths
    for cache in bpy.data.cache_files:
        if cache.filepath:
            if not refs_found:
                print("=== External References ===")
                refs_found = True
            print(f"cache: {cache.filepath}")

    if refs_found:
        print()


def main():
    print("=" * 60)
    print("Blender Data Extraction Report")
    print(f"File: {bpy.data.filepath}")
    print("=" * 60)
    print()

    extract_text_blocks()
    extract_driver_expressions()
    extract_node_scripts()
    extract_metadata()
    extract_external_refs()

    print("=" * 60)
    print("Extraction Complete")
    print("=" * 60)


if __name__ == "__main__":
    main()
