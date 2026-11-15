#!/usr/bin/env python3
"""生成浏览器演示用的 JPEG 原图 ZIP（基于 batch1 发布后的 v1 索引）。

运行：
    PYTHONPATH=. python3 scripts/make_demo_zips.py

产物（写入 samples/，可重复运行覆盖）：
  demo_good.zip       全部 6 张可解码 JPEG、路径齐全 → 审核通过、可交付
  demo_missing.zip    缺 cam02/20260301/P0004.jpg，且含一个包内多余文件
  demo_dupname.zip    P0002.jpg 在包内出现两次（同路径重复，且两份字节不同）
  demo_bad_all.zip    综合：缺图 + 同路径重复 + 非 JPEG 无法解码 + 字节碰撞

安全说明：本脚本只写 samples/ 目录；条目名使用索引里的相对路径，
且刻意打乱 ZIP 内条目顺序，演示"不按文件名排序/解压覆盖匹配"。
"""
from __future__ import annotations

import io
import zipfile
from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / "samples"

# 与 samples/batch1_base.csv 发布 v1 后的 rel_path 保持一致
REL_PATHS = [
    "cam01/20260301/P0002.jpg",
    "cam01/20260301/P0003.jpg",
    "cam01/20260301/P0005.jpg",
    "cam01/20260301/P0006.jpg",
    "cam02/20260301/P0001.jpg",
    "cam02/20260301/P0004.jpg",
]


def jpeg_bytes(label: str, color: tuple[int, int, int], size=(96, 72)) -> bytes:
    im = Image.new("RGB", size, color)
    draw = ImageDraw.Draw(im)
    draw.rectangle([8, 8, size[0] - 9, size[1] - 9], outline=(255, 255, 255), width=2)
    draw.text((14, 26), label, fill=(255, 255, 255))
    buf = io.BytesIO()
    im.save(buf, format="JPEG", quality=88)
    return buf.getvalue()


def make_images() -> dict[str, bytes]:
    palette = [
        (40, 90, 40), (70, 110, 50), (120, 80, 40), (140, 100, 60),
        (160, 60, 40), (50, 70, 130),
    ]
    images = {}
    for rel, color in zip(REL_PATHS, palette):
        images[rel] = jpeg_bytes(Path(rel).stem, color)
    return images


def write_zip(path: Path, members: list[tuple[str, bytes]]) -> None:
    """members: (条目名, 字节) 列表，按给定顺序写入（调用方可打乱顺序）。"""
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in members:
            zf.writestr(name, data)


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    images = make_images()

    # 1) 全部齐全且可解码（打乱顺序）
    shuffled = list(images.items())
    shuffled.reverse()
    write_zip(OUT_DIR / "demo_good.zip", shuffled)

    # 2) 缺 P0004 + 一个多余文件（多余文件不影响交付结论，仅统计）
    members = [(p, d) for p, d in images.items() if not p.endswith("P0004.jpg")]
    members.append(("README_demo.txt", "this file is not referenced by any index".encode()))
    write_zip(OUT_DIR / "demo_missing.zip", members)

    # 3) 同路径重复：P0002.jpg 出现两次且字节不同（中间插入其他条目，模拟乱序）
    other = [(p, d) for p, d in images.items() if not p.endswith("P0002.jpg")]
    dup_name = "cam01/20260301/P0002.jpg"
    members = [
        (other[0][0], other[0][1]),
        (dup_name, images[dup_name]),
        (other[1][0], other[1][1]),
        (dup_name, jpeg_bytes("P0002-DUP", (200, 30, 30))),  # 同路径、不同字节
    ]
    members += other[2:]
    write_zip(OUT_DIR / "demo_dupname.zip", members)

    # 4) 综合问题包
    #    - 缺 P0005.jpg
    #    - P0003.jpg 同路径重复
    #    - P0006.jpg 位置放一段非 JPEG 字节 → 无法解码
    #    - P0001.jpg 与 P0004.jpg 写入完全相同的 JPEG 字节 → 字节碰撞
    shared = jpeg_bytes("SAME-BYTES", (30, 30, 30))
    members = []
    for rel, data in images.items():
        if rel.endswith("P0005.jpg"):
            continue  # 缺图
        if rel.endswith("P0006.jpg"):
            members.append((rel, b"not-a-jpeg-binary"))
            continue
        if rel.endswith(("P0001.jpg", "P0004.jpg")):
            members.append((rel, shared))  # 不同照片号、相同字节
            continue
        members.append((rel, data))
    members.insert(2, ("cam01/20260301/P0003.jpg", jpeg_bytes("P0003-2ND", (9, 9, 9))))
    write_zip(OUT_DIR / "demo_bad_all.zip", members)

    for name in ("demo_good.zip", "demo_missing.zip", "demo_dupname.zip", "demo_bad_all.zip"):
        print("wrote", OUT_DIR / name)


if __name__ == "__main__":
    main()
