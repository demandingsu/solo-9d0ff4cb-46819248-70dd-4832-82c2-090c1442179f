"""ZIP 审核测试：四类问题、致命失败（解压上限/不安全路径/损坏包）、
版本绑定与报告原子性、旧版核对、报告写入失败不留半份结果。"""
from __future__ import annotations

import csv
import io
import sqlite3
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from PIL import Image

from app.audit import (
    AuditAborted,
    ExpectedPhoto,
    audit_zip,
    is_safe_member_name,
)
from app.main import Settings, create_app

# ---------------------------------------------------------------- 工具


def jpeg(label: str, color=(40, 90, 40), size=(64, 48)) -> bytes:
    # 像素随 label 变化，保证不同 label 的 JPEG 字节不同（避免纯色图误碰字节碰撞）
    seed = sum(map(ord, label))
    buf = io.BytesIO()
    im = Image.new("RGB", size, color)
    px = im.load()
    for x in range(size[0]):
        for y in range(size[1]):
            px[x, y] = ((x * 7 + seed) % 256, (y * 5 + seed) % 256, (x + y + seed) % 256)
    im.save(buf, format="JPEG", quality=85)
    return buf.getvalue()


EXPECTED_PATHS = [f"cam0{i}/20260301/P{i}.jpg" for i in range(1, 5)]
PHOTO_NOS = [f"P{i}" for i in range(1, 5)]


def make_expected() -> list[ExpectedPhoto]:
    return [ExpectedPhoto(no, path, "train") for no, path in zip(PHOTO_NOS, EXPECTED_PATHS)]


def write_zip(path: Path, members, compression=zipfile.ZIP_DEFLATED):
    with zipfile.ZipFile(path, "w", compression=compression) as zf:
        for name, data in members:
            zf.writestr(name, data)


@pytest.fixture()
def zip_dir(tmp_path):
    d = tmp_path / "zips"
    d.mkdir()
    return d


@pytest.fixture()
def env(tmp_path):
    settings = Settings(data_dir=tmp_path / "data", samples_dir=None)
    app = create_app(settings)
    client = TestClient(app, follow_redirects=True)
    return client, settings


def publish_v1(client, rel_paths=None):
    rel_paths = rel_paths or EXPECTED_PATHS
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["photo_no", "camera_no", "captured_at", "species", "rel_path"])
    for i, rel in enumerate(rel_paths):
        w.writerow([f"P{i + 1}", "CAM01", f"2026-03-01T08:00:{i:02d}Z", "boar", rel])
    r = client.post("/upload", files={"file": ("b1.csv", buf.getvalue().encode(), "text/csv")})
    assert "已发布版本 v1" in r.text


def post_audit(client, zip_path: Path, version_id=1, name=None):
    return client.post(
        "/audits",
        data={"version_id": str(version_id)},
        files={"file": (name or zip_path.name, zip_path.read_bytes(), "application/zip")},
        follow_redirects=True,
    )


def db_rows(settings):
    conn = sqlite3.connect(settings.db_path)
    conn.row_factory = sqlite3.Row
    try:
        return list(conn.execute("SELECT * FROM audits ORDER BY id"))
    finally:
        conn.close()


# ---------------------------------------------------------------- 单元：路径安全


@pytest.mark.parametrize(
    "name,ok",
    [
        ("cam01/a.jpg", True),
        ("a/b/c.jpg", True),
        ("/etc/passwd", False),
        ("../a.jpg", False),
        ("cam01/../a.jpg", False),
        ("cam01/./a.jpg", False),
        ("cam01//a.jpg", False),
        ("C:\\Windows\\a.jpg", False),
        ("cam01\\a.jpg", False),
        ("cam01/a.jpg/", False),
        ("", False),
    ],
)
def test_path_safety(name, ok):
    assert is_safe_member_name(name) is ok


# ---------------------------------------------------------------- 单元：四类问题


def test_clean_zip_passes(zip_dir):
    zp = zip_dir / "good.zip"
    write_zip(zp, [(p, jpeg(no)) for no, p in zip(PHOTO_NOS, EXPECTED_PATHS)])
    result = audit_zip(str(zp), make_expected())
    assert result.deliverable is True
    assert result.find()["missing"] == []


def test_missing_files_reported(zip_dir):
    zp = zip_dir / "missing.zip"
    write_zip(zp, [(p, jpeg(no)) for no, p in list(zip(PHOTO_NOS, EXPECTED_PATHS))[:2]])
    result = audit_zip(str(zp), make_expected())
    missing = result.find()["missing"]
    assert {m["rel_path"] for m in missing} == set(EXPECTED_PATHS[2:])
    assert result.deliverable is False


def test_duplicate_same_path_all_occurrences_recorded(zip_dir):
    """同路径重复不能依赖解压覆盖：两个条目都要被记录，顺序打乱也一样。"""
    zp = zip_dir / "dup.zip"
    target = EXPECTED_PATHS[0]
    members = [
        (EXPECTED_PATHS[1], jpeg("P2")),
        (target, jpeg("FIRST", (1, 1, 1))),
        (EXPECTED_PATHS[2], jpeg("P3")),
        (target, jpeg("SECOND", (2, 2, 2))),  # 同路径、不同字节
        (EXPECTED_PATHS[3], jpeg("P4")),
    ]
    write_zip(zp, members)
    result = audit_zip(str(zp), make_expected())
    dup = result.find()["duplicate"]
    assert len(dup) == 1 and dup[0]["rel_path"] == target
    assert len(dup[0]["occurrences"]) == 2
    assert dup[0]["occurrences"][0]["sha256"] != dup[0]["occurrences"][1]["sha256"]


def test_undecodable_entry_reported(zip_dir):
    zp = zip_dir / "bad.jpg.zip"
    members = [(p, jpeg(no)) for no, p in zip(PHOTO_NOS, EXPECTED_PATHS)]
    members[1] = (EXPECTED_PATHS[1], b"this is definitely not a jpeg")
    write_zip(zp, members)
    result = audit_zip(str(zp), make_expected())
    bad = result.find()["undecodable"]
    assert len(bad) == 1 and bad[0]["rel_path"] == EXPECTED_PATHS[1]
    assert "UnidentifiedImageError" in bad[0]["reason"]


def test_png_bytes_flagged_as_not_jpeg(zip_dir):
    zp = zip_dir / "png.zip"
    png_buf = io.BytesIO()
    Image.new("RGB", (8, 8), (1, 2, 3)).save(png_buf, format="PNG")
    members = [(p, jpeg(no)) for no, p in zip(PHOTO_NOS, EXPECTED_PATHS)]
    members[0] = (EXPECTED_PATHS[0], png_buf.getvalue())
    write_zip(zp, members)
    result = audit_zip(str(zp), make_expected())
    bad = result.find()["undecodable"]
    assert len(bad) == 1 and "不是 JPEG" in bad[0]["reason"]


def test_truncated_jpeg_reported(zip_dir):
    zp = zip_dir / "trunc.zip"
    good = jpeg("X")
    members = [(p, jpeg(no)) for no, p in zip(PHOTO_NOS, EXPECTED_PATHS)]
    members[0] = (EXPECTED_PATHS[0], good[: len(good) // 2])  # 截断的 JPEG
    write_zip(zp, members)
    result = audit_zip(str(zp), make_expected())
    assert len(result.find()["undecodable"]) == 1


def test_byte_collision_different_photo_no_same_bytes(zip_dir):
    zp = zip_dir / "collision.zip"
    shared = jpeg("SAME", (7, 7, 7))
    members = [(p, jpeg(no)) for no, p in zip(PHOTO_NOS, EXPECTED_PATHS)]
    members[0] = (EXPECTED_PATHS[0], shared)
    members[2] = (EXPECTED_PATHS[2], shared)  # P1 与 P3 字节完全相同
    write_zip(zp, members)
    result = audit_zip(str(zp), make_expected())
    collisions = result.find()["byte_collision"]
    assert len(collisions) == 1
    assert set(collisions[0]["photo_nos"]) == {"P1", "P3"}


def test_identical_bytes_under_same_photo_no_is_not_collision(zip_dir):
    """同路径重复且两份字节相同：算 duplicate，不算跨照片号字节碰撞。"""
    zp = zip_dir / "same-twice.zip"
    shared = jpeg("X")
    members = [(p, jpeg(no)) for no, p in zip(PHOTO_NOS, EXPECTED_PATHS)]
    members[0] = (EXPECTED_PATHS[0], shared)
    members.append((EXPECTED_PATHS[0], shared))
    write_zip(zp, members)
    result = audit_zip(str(zp), make_expected())
    findings = result.find()
    assert len(findings["duplicate"]) == 1
    assert findings["byte_collision"] == []


def test_extra_files_counted_but_not_failure(zip_dir):
    zp = zip_dir / "extra.zip"
    members = [(p, jpeg(no)) for no, p in zip(PHOTO_NOS, EXPECTED_PATHS)]
    members.append(("notes/readme.txt", b"hello"))
    write_zip(zp, members)
    result = audit_zip(str(zp), make_expected())
    assert result.deliverable is True
    assert result.extra_files == ["notes/readme.txt"]


def test_oversized_pixel_image_rejected(zip_dir, monkeypatch):
    """像素超安全上限的图片判无法解码（不实际分配巨量内存）。"""
    import app.audit as audit_mod

    monkeypatch.setattr(audit_mod, "MAX_IMAGE_PIXELS", 100)  # 64x48=3072 > 100
    zp = zip_dir / "hugepx.zip"
    write_zip(zp, [(p, jpeg(no)) for no, p in zip(PHOTO_NOS, EXPECTED_PATHS)])
    result = audit_zip(str(zp), make_expected())
    bad = result.find()["undecodable"]
    assert len(bad) == 4 and all("安全上限" in x["reason"] for x in bad)


# ---------------------------------------------------------------- 单元：致命失败


def test_unsafe_traversal_path_aborts_entire_audit(zip_dir):
    zp = zip_dir / "evil.zip"
    write_zip(zp, [("../escape.jpg", jpeg("X")), (EXPECTED_PATHS[0], jpeg("P1"))])
    with pytest.raises(AuditAborted) as ei:
        audit_zip(str(zp), make_expected())
    assert "路径不安全" in str(ei.value)


def test_absolute_path_aborts(zip_dir):
    zp = zip_dir / "abs.zip"
    write_zip(zp, [("/abs/a.jpg", jpeg("X"))])
    with pytest.raises(AuditAborted):
        audit_zip(str(zp), make_expected())


def test_corrupt_zip_aborts(zip_dir):
    zp = zip_dir / "broken.zip"
    zp.write_bytes(b"PK\x03\x04 not really a zip" + b"\x00" * 50)
    with pytest.raises(AuditAborted) as ei:
        audit_zip(str(zp), make_expected())
    assert "压缩包损坏" in str(ei.value)


def test_crc_error_aborts(zip_dir):
    """篡改 ZIP 内一个条目的压缩流导致 CRC/解压失败 -> 整次审核失败。"""
    import struct

    zp = zip_dir / "crc.zip"
    write_zip(zp, [(p, jpeg(no)) for no, p in zip(PHOTO_NOS, EXPECTED_PATHS)])
    raw = bytearray(zp.read_bytes())
    # 本地文件头：签名(4)+版本(2)+标志(2)+压缩方式(2)+时间(4)+CRC(4)
    # +压缩大小(4)+原始大小(4)+文件名长度(2)+额外字段长度(2)
    name_len = struct.unpack_from("<H", raw, 26)[0]
    extra_len = struct.unpack_from("<H", raw, 28)[0]
    data_start = 30 + name_len + extra_len
    raw[data_start + 3] ^= 0xFF  # 翻转压缩数据区的一个字节，破坏 DEFLATE 流或 CRC
    zp.write_bytes(bytes(raw))
    with pytest.raises(AuditAborted):
        audit_zip(str(zp), make_expected())


def test_uncompressed_limit_aborts(zip_dir):
    """累计解压量超上限立即中止（用很小的上限模拟 200MB 约束）。"""
    zp = zip_dir / "big.zip"
    # 用 STORED 存不可压缩的随机数据
    import os as _os

    blob = _os.urandom(50_000)
    write_zip(zp, [(EXPECTED_PATHS[0], blob)], compression=zipfile.ZIP_STORED)
    with pytest.raises(AuditAborted) as ei:
        audit_zip(str(zp), make_expected(), max_uncompressed_bytes=1024)
    assert "累计解压量超过" in str(ei.value)


def test_zip_bomb_compression_ratio_trips_limit(zip_dir):
    """高压缩比 ZIP 炸弹：压缩体积小，但解压量在流式累计时撞上上限。"""
    zp = zip_dir / "bomb.zip"
    huge = b"A" * (100_000)
    write_zip(zp, [(EXPECTED_PATHS[0], huge)])
    assert zp.stat().st_size < 5_000  # 压缩后很小
    with pytest.raises(AuditAborted):
        audit_zip(str(zp), make_expected(), max_uncompressed_bytes=10_000)


def test_symlink_entry_aborts(zip_dir):
    """显式符号链接条目（Unix mode）必须拒绝。"""
    import stat as st

    zp = zip_dir / "link.zip"
    with zipfile.ZipFile(zp, "w") as zf:
        info = zipfile.ZipInfo("link.jpg")
        info.create_system = 3
        info.external_attr = (st.S_IFLNK | 0o777) << 16
        zf.writestr(info, "target.jpg")
        zf.writestr(EXPECTED_PATHS[0], jpeg("P1"))
    with pytest.raises(AuditAborted) as ei:
        audit_zip(str(zp), make_expected())
    assert "符号链接" in str(ei.value)


# ---------------------------------------------------------------- 端到端：HTTP/页面/报告


def test_e2e_good_zip_passes_and_report_bound(env, tmp_path):
    client, settings = env
    publish_v1(client)
    zp = tmp_path / "good.zip"
    write_zip(zp, [(p, jpeg(no)) for no, p in zip(PHOTO_NOS, EXPECTED_PATHS)])
    r = post_audit(client, zp)
    assert r.status_code == 200 and "可交付" in r.text

    rows = db_rows(settings)
    assert len(rows) == 1
    row = rows[0]
    assert row["status"] == "passed" and row["deliverable"] == 1
    assert len(row["zip_sha256"]) == 64 and row["version_id"] == 1

    rep = client.get("/audits/1/report").json()
    assert rep["zip_sha256"] == row["zip_sha256"]
    assert rep["version_id"] == 1 and rep["deliverable"] is True
    assert rep["index_summary"]["expected_count"] == 4


def test_e2e_issues_zip_not_deliverable(env, tmp_path):
    client, settings = env
    publish_v1(client)
    zp = tmp_path / "bad.zip"
    write_zip(zp, [(p, jpeg(no)) for no, p in list(zip(PHOTO_NOS, EXPECTED_PATHS))[:3]])
    r = post_audit(client, zp)
    assert "不可交付" in r.text and "缺图" in r.text
    row = db_rows(settings)[0]
    assert row["status"] == "issues" and row["missing_count"] == 1


def test_e2e_abort_leaves_no_partial_report(env, tmp_path):
    """致命失败：只有 aborted 记录与原因，没有报告文件，下载报告 404。"""
    client, settings = env
    publish_v1(client)
    zp = tmp_path / "evil.zip"
    write_zip(zp, [("../escape.jpg", jpeg("X"))])
    r = post_audit(client, zp)
    assert r.status_code == 200 and "整次审核失败" in r.text and "路径不安全" in r.text
    row = db_rows(settings)[0]
    assert row["status"] == "aborted" and row["report_path"] == ""
    assert list((settings.data_dir / "audits").iterdir()) == []
    assert client.get("/audits/1/report").status_code == 404
    # 页面上不出现任何问题分区数据
    assert "问题汇总" not in r.text


def test_e2e_corrupt_zip_aborts(env, tmp_path):
    client, settings = env
    publish_v1(client)
    zp = tmp_path / "broken.zip"
    zp.write_bytes(b"not a zip at all")
    r = post_audit(client, zp)
    assert "整次审核失败" in r.text and "压缩包损坏" in r.text
    assert db_rows(settings)[0]["status"] == "aborted"


def test_audit_against_old_version_after_new_batch(env, tmp_path):
    """发布 v2 后仍选择 v1 核对：报告必须绑定 v1 的冻结索引。"""
    client, settings = env
    publish_v1(client)
    v1_paths = list(EXPECTED_PATHS)

    # 第二批：新增 P5，发布 v2
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["photo_no", "camera_no", "captured_at", "species", "rel_path"])
    w.writerow(["P5", "CAM02", "2026-03-02T09:00:00Z", "fox", "cam02/P5.jpg"])
    r = client.post("/upload", files={"file": ("b2.csv", buf.getvalue().encode(), "text/csv")})
    assert "已发布版本 v2" in r.text

    # 只含 v1 四张图的 ZIP，对 v1 审核应通过；对 v2 审核应缺一张
    zp = tmp_path / "v1.zip"
    write_zip(zp, [(p, jpeg(no)) for no, p in zip(PHOTO_NOS, v1_paths)])

    r1 = post_audit(client, zp, version_id=1)
    assert "可交付" in r1.text
    assert db_rows(settings)[-1]["version_id"] == 1

    r2 = post_audit(client, zp, version_id=2)
    assert "不可交付" in r2.text and "cam02/P5.jpg" in r2.text
    last = db_rows(settings)[-1]
    assert last["version_id"] == 2 and last["missing_count"] == 1


def test_report_write_failure_rolls_back_with_half_result(env, tmp_path, monkeypatch):
    """报告文件写入失败：事务回滚，页面/库里都没有半份审核记录。"""
    client, settings = env
    publish_v1(client)
    zp = tmp_path / "good.zip"
    write_zip(zp, [(p, jpeg(no)) for no, p in zip(PHOTO_NOS, EXPECTED_PATHS)])

    import app.main as main

    def boom(*a, **kw):
        raise OSError("模拟报告盘故障")

    monkeypatch.setattr(main, "_write_audit_report", boom)
    r = post_audit(client, zp)
    assert r.status_code == 200 and "审核记录写入失败" in r.text
    assert db_rows(settings) == []  # 插入的 aborted 占位行也随事务回滚
    assert list((settings.data_dir / "audits").iterdir()) == []
    assert client.get("/audits/1").status_code == 404


def test_same_zip_digest_stable_across_audits(env, tmp_path):
    client, settings = env
    publish_v1(client)
    zp = tmp_path / "good.zip"
    write_zip(zp, [(p, jpeg(no)) for no, p in zip(PHOTO_NOS, EXPECTED_PATHS)])
    post_audit(client, zp, name="a.zip")
    post_audit(client, zp, name="b.zip")  # 同字节换文件名
    rows = db_rows(settings)
    assert len(rows) == 2
    assert rows[0]["zip_sha256"] == rows[1]["zip_sha256"]
    assert rows[0]["zip_filename"] != rows[1]["zip_filename"]


def test_audit_nonexistent_version_rejected(env, tmp_path):
    client, settings = env
    publish_v1(client)
    zp = tmp_path / "good.zip"
    write_zip(zp, [(p, jpeg(no)) for no, p in zip(PHOTO_NOS, EXPECTED_PATHS)])
    r = post_audit(client, zp, version_id=99)
    assert r.status_code == 200 and "不存在" in r.text
    assert db_rows(settings) == []


def test_home_and_version_pages_show_audit_sections(env, tmp_path):
    client, settings = env
    publish_v1(client)
    home = client.get("/").text
    assert "JPEG 原图 ZIP 审核" in home
    zp = tmp_path / "good.zip"
    write_zip(zp, [(p, jpeg(no)) for no, p in zip(PHOTO_NOS, EXPECTED_PATHS)])
    post_audit(client, zp)
    home = client.get("/").text
    assert "ZIP 审核记录" in home and "可交付" in home
    vpage = client.get("/versions/1").text
    assert "本版本最近 ZIP 审核" in vpage


def test_original_upload_and_download_unchanged(env):
    """新增审核功能不影响原有 CSV 上传与索引下载。"""
    client, settings = env
    publish_v1(client)
    train = client.get("/versions/1/files/train_index.csv")
    val = client.get("/versions/1/files/val_index.csv")
    assert train.status_code == val.status_code == 200
    all_nos = [r["photo_no"] for r in csv.DictReader(io.StringIO(train.text))]
    all_nos += [r["photo_no"] for r in csv.DictReader(io.StringIO(val.text))]
    assert sorted(all_nos) == PHOTO_NOS
