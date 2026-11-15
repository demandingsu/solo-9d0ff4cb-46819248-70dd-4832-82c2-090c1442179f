"""JPEG 原图 ZIP 审核（纯扫描逻辑，不向磁盘解压）。

审核口径
--------
针对某个**已发布版本**的两份冻结索引（train/val），按其中每条记录的
``rel_path`` 在上传的 ZIP 内查找对应条目（ZIP 条目顺序任意，不依赖文件名
排序，也不做"解压覆盖"式匹配——同路径的每个条目都单独记录），报告四类问题：

1. ``missing``       索引要求的 rel_path 在包内不存在（缺图）；
2. ``duplicate``     同一 rel_path 在包内出现多次（包内同路径重复）；
3. ``undecodable``   条目存在但 Pillow 无法按 JPEG 解码（无法解码）；
4. ``byte_collision`` 不同 photo_no 对应的图片字节完全相同（sha256 相同）。

整次审核失败（不产出部分报告）的情形：

* 累计**解压字节数**超过上限（默认 200MB，按读取流累计，防 ZIP 炸弹）；
* 条目路径不安全（绝对路径、含 ``..``、盘符/反斜杠、符号链接等）；
* 压缩包本身损坏（无法打开中央目录、读取报错、CRC 校验失败等）。

实现不把任何条目写到磁盘：全部在内存中流式读取，且总解压量被硬上限约束。
"""

from __future__ import annotations

import hashlib
import io
import stat
import zipfile
import zlib
from dataclasses import dataclass, field

from PIL import Image

DEFAULT_MAX_UNCOMPRESSED_BYTES = 200 * 1024 * 1024  # 累计解压量 200MB 硬上限
# 单张图片解码像素上限（约 1.2 亿像素），超尺寸的异常图片直接判无法解码，
# 与 Pillow 自带的 DecompressionBomb 保护形成双重防线。
MAX_IMAGE_PIXELS = 120_000_000

# 读取 ZIP 流时视为"压缩包损坏"的解压错误
_ZIP_READ_ERRORS = (zipfile.BadZipFile, OSError, zlib.error, RuntimeError)


class AuditAborted(Exception):
    """整次审核失败：调用方只能记录失败原因，不得保留任何部分审核结果。"""


# ---------------------------------------------------------------- 数据结构


@dataclass(frozen=True)
class ExpectedPhoto:
    photo_no: str
    rel_path: str
    split: str  # "train" | "val"


@dataclass
class EntryRead:
    """ZIP 中一个条目的读取结果（同路径可能有多个，各自独立记录）。"""

    ordinal: int
    size: int
    sha256: str
    decode_error: str | None  # None = 可按 JPEG 正常解码


@dataclass
class AuditResult:
    expected: list[ExpectedPhoto]
    entries: dict[str, list[EntryRead]] = field(default_factory=dict)
    extra_files: list[str] = field(default_factory=list)
    scanned_bytes: int = 0
    entry_count: int = 0  # 实际读取的文件条目数（不含目录）

    def find(self) -> dict:
        """汇总四类问题。全部为空时调用方才可标记可交付。"""
        missing: list[dict] = []
        duplicate: list[dict] = []
        undecodable: list[dict] = []

        # rel_path -> 该路径在索引中对应的照片号（正常情况恰好一个）
        path_photos: dict[str, list[str]] = {}
        for p in self.expected:
            path_photos.setdefault(p.rel_path, []).append(p.photo_no)

        for rel_path in sorted(path_photos):
            reads = self.entries.get(rel_path)
            if not reads:
                missing.append({
                    "rel_path": rel_path,
                    "photo_nos": sorted(set(path_photos[rel_path])),
                })
                continue
            if len(reads) > 1:
                duplicate.append({
                    "rel_path": rel_path,
                    "photo_nos": sorted(set(path_photos[rel_path])),
                    "occurrences": [
                        {"ordinal": r.ordinal, "size": r.size, "sha256": r.sha256}
                        for r in reads
                    ],
                })
            for r in reads:
                if r.decode_error is not None:
                    undecodable.append({
                        "rel_path": rel_path,
                        "ordinal": r.ordinal,
                        "size": r.size,
                        "reason": r.decode_error,
                    })

        # 字节碰撞：只统计能正常解码的条目，按 sha256 归组，
        # 组内涉及 ≥2 个不同 photo_no 即命中。
        digest_buckets: dict[str, dict] = {}
        for rel_path, reads in self.entries.items():
            photo_nos = set(path_photos.get(rel_path, ()))
            if not photo_nos:
                continue  # 包内多余文件不参与碰撞分析
            for r in reads:
                if r.decode_error is not None:
                    continue
                bucket = digest_buckets.setdefault(r.sha256, {"photo_nos": set(), "files": []})
                bucket["photo_nos"].update(photo_nos)
                bucket["files"].append({
                    "rel_path": rel_path,
                    "ordinal": r.ordinal,
                    "photo_nos": sorted(photo_nos),
                })
        byte_collisions = []
        for digest in sorted(digest_buckets):
            bucket = digest_buckets[digest]
            if len(bucket["photo_nos"]) >= 2:
                byte_collisions.append({
                    "sha256": digest,
                    "photo_nos": sorted(bucket["photo_nos"]),
                    "files": sorted(bucket["files"], key=lambda f: (f["rel_path"], f["ordinal"])),
                })

        return {
            "missing": missing,
            "duplicate": duplicate,
            "undecodable": undecodable,
            "byte_collision": byte_collisions,
        }

    @property
    def deliverable(self) -> bool:
        findings = self.find()
        return not any(findings.values())


# ---------------------------------------------------------------- 路径安全

def is_safe_member_name(name: str) -> bool:
    """ZIP 条目名必须是相对的、不含穿越/盘符/反斜杠的普通路径。"""
    if not name or name.endswith("/"):
        return False  # 目录条目由调用方先过滤，这里视为不可接受
    if "\x00" in name or "\\" in name or ":" in name:
        return False  # Windows 盘符/反斜杠/空字节一律拒绝
    if name.startswith("/"):
        return False  # 绝对路径
    parts = name.split("/")
    if any(part in ("", ".", "..") for part in parts):
        return False  # 穿越段、空段（含 // 与 ./ 开头）
    return True


def _is_regular_file(info: zipfile.ZipInfo) -> bool:
    """非 Unix 来源的条目按普通文件处理；Unix 来源仅拒绝明确的非常规类型。

    许多打包工具（含 Python ``writestr``）只写权限位、不写文件类型位
    （如 mode=0o600 而非 0o100600），因此类型位缺失时按普通文件放行；
    只有显式标注为符号链接/设备/FIFO/socket 才拒绝。目录条目已在调用前过滤。
    """
    if info.create_system != 3:  # 3 = Unix
        return True
    mode = info.external_attr >> 16
    if mode == 0:
        return True
    # 命中任何明确的非常规类型即拒绝
    if stat.S_ISLNK(mode) or stat.S_ISCHR(mode) or stat.S_ISBLK(mode) or stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode):
        return False
    return True


# ---------------------------------------------------------------- JPEG 解码

def decode_jpeg_error(data: bytes) -> str | None:
    """返回 None 表示可按 JPEG 正常解码；否则返回中文原因。"""
    fmt = None
    try:
        with Image.open(io.BytesIO(data)) as im:
            fmt = im.format
            width, height = im.size
            if width * height > MAX_IMAGE_PIXELS:
                return f"图片像素 {width}x{height} 超过安全上限，拒绝解码"
            im.verify()  # 校验文件结构与编码完整性（verify 后对象不可再用）
        with Image.open(io.BytesIO(data)) as im:
            im.load()  # 重新打开做一次完整像素解码，覆盖截断等 verify 漏掉的问题
    except Exception as exc:  # Pillow 抛出的各种解码异常统一归类
        return f"{type(exc).__name__}: {exc}"
    if fmt != "JPEG":
        return f"不是 JPEG 图片（实际格式: {fmt or '未知'}）"
    return None


# ---------------------------------------------------------------- 主扫描

def audit_zip(
    zip_path: str,
    expected: list[ExpectedPhoto],
    max_uncompressed_bytes: int = DEFAULT_MAX_UNCOMPRESSED_BYTES,
) -> AuditResult:
    """扫描 ZIP 并返回完整 :class:`AuditResult`。

    任何致命问题抛 :class:`AuditAborted`，此时不会返回部分结果，
    调用方也不得把已扫描到的内容写成报告。
    """
    try:
        zf = zipfile.ZipFile(zip_path)
    except zipfile.BadZipFile as exc:
        raise AuditAborted(f"压缩包损坏，无法打开：{exc}") from exc
    except OSError as exc:
        raise AuditAborted(f"压缩包无法读取：{exc}") from exc

    result = AuditResult(expected=expected)
    expected_paths = {p.rel_path for p in expected}

    with zf:
        infos = [i for i in zf.infolist() if not i.is_dir()]

        # 先整体预审路径与条目类型：有任何不安全条目，在解压任何字节之前失败。
        for info in infos:
            if not is_safe_member_name(info.filename):
                raise AuditAborted(f"路径不安全，整次审核失败：{info.filename!r}")
            if not _is_regular_file(info):
                raise AuditAborted(f"条目不是普通文件（疑似符号链接/设备），整次审核失败：{info.filename!r}")

        for ordinal, info in enumerate(infos, start=1):
            try:
                stream = zf.open(info)
            except _ZIP_READ_ERRORS as exc:  # 加密条目、中央目录损坏等
                raise AuditAborted(f"条目无法读取，整次审核失败：{info.filename!r}（{exc}）") from exc

            hasher = hashlib.sha256()
            chunks: list[bytes] = []
            with stream:
                while True:
                    try:
                        chunk = stream.read(1024 * 1024)
                    except _ZIP_READ_ERRORS as exc:  # CRC 失败/截断/解压错误
                        raise AuditAborted(
                            f"压缩包损坏，读取条目失败：{info.filename!r}（{exc}）"
                        ) from exc
                    if not chunk:
                        break
                    result.scanned_bytes += len(chunk)
                    if result.scanned_bytes > max_uncompressed_bytes:
                        raise AuditAborted(
                            f"累计解压量超过 {max_uncompressed_bytes} 字节上限，"
                            "整次审核失败（疑似 ZIP 炸弹）"
                        )
                    hasher.update(chunk)
                    if info.filename in expected_paths:
                        # 只保留索引要求的文件字节；多余文件不占内存
                        chunks.append(chunk)

            result.entry_count += 1
            if info.filename not in expected_paths:
                result.extra_files.append(info.filename)
                continue

            data = b"".join(chunks)
            error = decode_jpeg_error(data)
            result.entries.setdefault(info.filename, []).append(
                EntryRead(
                    ordinal=ordinal,
                    size=len(data),
                    sha256=hasher.hexdigest(),
                    decode_error=error,
                )
            )

    return result
