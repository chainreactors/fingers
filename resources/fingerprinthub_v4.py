#!/usr/bin/env python3
"""
合并 FingerprintHub 的 web 和 service 指纹到 JSON 文件并压缩
"""
import os
import yaml
import json
import gzip
from pathlib import Path

def merge_fingerprints(source_dir, output_file, fingerprint_type="web"):
    """
    将所有 yaml 文件合并到一个 JSON 文件

    Args:
        source_dir: 指纹目录路径
        output_file: 输出的 JSON 文件路径
        fingerprint_type: 指纹类型 (web 或 service)
    """
    fingerprints = []
    loaded_count = 0
    failed_count = 0
    errors = []

    print(f"\n{'='*60}")
    print(f"Processing {fingerprint_type.upper()} fingerprints")
    print(f"{'='*60}")
    print(f"Scanning directory: {source_dir}")

    # 遍历所有 yaml 文件
    yaml_files = list(Path(source_dir).rglob("*.yaml")) + list(Path(source_dir).rglob("*.yml"))
    total = len(yaml_files)

    print(f"Found {total} yaml files")
    print("Loading...")

    for i, yaml_file in enumerate(yaml_files):
        try:
            with open(yaml_file, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
                if data:
                    # 添加文件路径信息用于调试
                    data['_source_file'] = str(yaml_file.relative_to(source_dir))
                    fingerprints.append(data)
                    loaded_count += 1
        except Exception as e:
            failed_count += 1
            if len(errors) < 10:
                errors.append(f"{yaml_file.name}: {str(e)[:50]}")

        # 显示进度
        if (i + 1) % 100 == 0 or (i + 1) == total:
            print(f"Progress: {i+1}/{total} ({(i+1)/total*100:.1f}%)")

    print(f"\nLoaded: {loaded_count}")
    print(f"Failed: {failed_count}")

    if errors:
        print(f"\nFirst {len(errors)} errors:")
        for err in errors:
            print(f"  - {err}")

    # 保存为 JSON
    json_file = output_file.replace('.gz', '')
    print(f"\nSaving to {json_file}...")
    with open(json_file, 'w', encoding='utf-8') as f:
        json.dump(fingerprints, f, ensure_ascii=False)

    # 压缩为 gzip
    print(f"Compressing to {output_file}...")
    with open(json_file, 'rb') as f_in:
        with gzip.open(output_file, 'wb', compresslevel=9) as f_out:
            f_out.writelines(f_in)

    # 删除未压缩的 JSON 文件
    os.remove(json_file)

    # 统计信息
    file_size = os.path.getsize(output_file)
    print(f"Done! Saved {loaded_count} fingerprints")
    print(f"Compressed file size: {file_size / 1024:.2f} KB ({file_size / 1024 / 1024:.2f} MB)")

    return loaded_count, failed_count

def process_fingerprinthub(base_dir, output_dir):
    """
    处理 FingerprintHub 的 web 和 service 指纹

    Args:
        base_dir: FingerprintHub 根目录
        output_dir: 输出目录
    """
    base_path = Path(base_dir)
    output_path = Path(output_dir)

    # 确保输出目录存在
    output_path.mkdir(parents=True, exist_ok=True)

    results = {}

    # 处理 web-fingerprint
    web_dir = base_path / "web-fingerprint"
    if web_dir.exists():
        web_output = output_path / "fingerprinthub_web.json.gz"
        web_count, web_failed = merge_fingerprints(web_dir, str(web_output), "web")
        results['web'] = {'count': web_count, 'failed': web_failed}
    else:
        print(f"\n⚠️  Web fingerprint directory not found: {web_dir}")

    # 处理 service-fingerprint
    service_dir = base_path / "service-fingerprint"
    if service_dir.exists():
        service_output = output_path / "fingerprinthub_service.json.gz"
        service_count, service_failed = merge_fingerprints(service_dir, str(service_output), "service")
        results['service'] = {'count': service_count, 'failed': service_failed}
    else:
        print(f"\n⚠️  Service fingerprint directory not found: {service_dir}")

    # 打印总结
    print(f"\n{'='*60}")
    print("SUMMARY")
    print(f"{'='*60}")
    if 'web' in results:
        print(f"Web fingerprints:     {results['web']['count']} loaded, {results['web']['failed']} failed")
    if 'service' in results:
        print(f"Service fingerprints: {results['service']['count']} loaded, {results['service']['failed']} failed")
    print(f"{'='*60}\n")

    return results

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python fingerprinthub_v4.py <FingerprintHub-dir> [output-dir]")
        print()
        print("Example:")
        print("  python fingerprinthub_v4.py ../refer/FingerprintHub .")
        print()
        print("This will process both web-fingerprint and service-fingerprint directories")
        print("and generate compressed JSON files.")
        sys.exit(1)

    base_dir = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "."

    if not os.path.exists(base_dir):
        print(f"Error: Directory not found: {base_dir}")
        sys.exit(1)

    process_fingerprinthub(base_dir, output_dir)
