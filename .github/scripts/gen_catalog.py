#!/usr/bin/env python3
"""
为 ColorOS 歌词源镜像仓生成商店目录（catalog/stable.json）。

与 LyricProvider 仓的 gen_catalog.py 同一套规范：payload 字段、校验取值范围、
信封签名（ECDSA P-256 / SHA-256，签名原文 b"CLL-CATALOG-V1\\n" + payload）完全一致。
差别只有条目推导：这个仓的模块名本身就是 providerId（player-qishui、universal-provider …），
kind 按模块前缀推导。
"""

import argparse
import base64
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile

DOMAIN = b"CLL-CATALOG-V1\n"
PROVIDER_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
APPLICATION_ID = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")

TRUSTED_HOSTS = ["github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"]


def find_aapt():
    home = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    if not home:
        return None
    build_tools = os.path.join(home, "build-tools")
    if not os.path.isdir(build_tools):
        return None
    for name in sorted(os.listdir(build_tools), reverse=True):
        for binary in ("aapt2", "aapt"):
            path = os.path.join(build_tools, name, binary)
            if os.path.isfile(path) and os.access(path, os.X_OK):
                return path
    return None


def pick_label(out):
    """从 aapt badging 里挑展示名：优先中文标签，其次默认标签。"""
    candidates = []
    for key in ("zh-CN", "zh-Hans-CN", "zh", ""):
        suffix = ("-" + key) if key else ""
        pattern = "application-label" + re.escape(suffix) + r":'((?:\\.[^'])*)'"
        match = re.search(pattern, out)
        if match:
            raw = match.group(1)
            raw = raw.replace("\\'", "'").replace("\\\\", "\\")
            candidates.append(raw)
    for raw in candidates:
        text = re.sub(r"\\s+", " ", raw).strip()
        if text:
            return text[:40]
    return None


def dump_badging(aapt, apk):
    out = subprocess.run(
        [aapt, "dump", "badging", apk],
        check=True, capture_output=True, text=True,
    ).stdout
    package = re.search(r"package: name='([^']+)' versionCode='(\d+)' versionName='([^']*)'", out)
    if not package:
        raise SystemExit("无法从 %s 解析包信息" % apk)
    min_sdk = re.search(r"sdkVersion:'(\d+)'", out)
    return {
        "applicationId": package.group(1),
        "versionCode": int(package.group(2)),
        "versionName": package.group(3),
        "minSdk": int(min_sdk.group(1)) if min_sdk else 21,
        "displayName": pick_label(out),
    }


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def apk_signer_sha256(apksigner, apk):
    out = subprocess.run(
        [apksigner, "verify", "--print-certs", apk],
        check=True, capture_output=True, text=True,
    ).stdout
    match = re.search(r"certificate SHA-256 digest:\s*([0-9a-f]{64})", out)
    if not match:
        raise SystemExit("无法读取 %s 的签名证书" % apk)
    return match.group(1)


def kind_of(module):
    if module == "universal-provider":
        return "universal-lyrics"
    if module.startswith("artwork-provider"):
        return "artwork"
    return "dedicated-lyrics"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apk-dir")
    parser.add_argument("--repo")
    parser.add_argument("--tag")
    parser.add_argument("--commit")
    parser.add_argument("--resign-from", help="给已有信封：只更新 revision 与有效期，条目原样保留")
    parser.add_argument("--key", required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--revision", required=True, type=int)
    parser.add_argument("--validity-days", type=int, default=180)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())

    if args.resign_from:
        with open(args.resign_from, "r", encoding="utf-8") as handle:
            envelope = json.load(handle)
        payload = json.loads(base64.b64decode(envelope["payload"]))
        entries = payload["entries"]
        if not entries:
            raise SystemExit("已有目录里没有条目")
    else:
        for name in ("apk_dir", "repo", "tag", "commit"):
            if not getattr(args, name):
                raise SystemExit("构建模式下 --%s 必填" % name.replace("_", "-"))
        aapt = find_aapt()
        if not aapt:
            raise SystemExit("找不到 aapt2/aapt，无法读取 APK 元信息")
        apksigner = os.path.join(os.path.dirname(aapt), "apksigner")
        if not os.path.isfile(apksigner):
            raise SystemExit("找不到 apksigner")
        if not HEX40.match(args.commit):
            raise SystemExit("commit 必须是 40 位十六进制")

        entries = []
        for name in sorted(os.listdir(args.apk_dir)):
            if not name.endswith("-release.apk"):
                continue
            module = name[: -len("-release.apk")]
            if not PROVIDER_ID.match(module):
                print("跳过 providerId 不合规的模块：%s" % module, file=sys.stderr)
                continue
            apk_path = os.path.join(args.apk_dir, name)
            info = dump_badging(aapt, apk_path)
            if not APPLICATION_ID.match(info["applicationId"]):
                print("跳过 applicationId 不合规的模块：%s" % module, file=sys.stderr)
                continue
            if info["versionCode"] < 1:
                print("跳过 versionCode 不合规的模块：%s" % module, file=sys.stderr)
                continue
            entry = {
                "providerId": module,
                "kind": kind_of(module),
                "applicationId": info["applicationId"],
                "versionName": info["versionName"] or "unknown",
                "versionCode": info["versionCode"],
                "minSdk": info["minSdk"],
                "minStoreProtocol": 1,
                "sourceCommit": args.commit,
                "artifact": {
                    "urls": [
                        "https://github.com/%s/releases/download/%s/%s" % (args.repo, args.tag, name)
                    ],
                    "bytes": os.path.getsize(apk_path),
                    "sha256": sha256_file(apk_path),
                    "signerSha256": [apk_signer_sha256(apksigner, apk_path)],
                },
            }
            if info.get("displayName"):
                entry["displayName"] = info["displayName"]
            entries.append(entry)

    if not entries:
        raise SystemExit("没有可发布的 APK 条目")

    payload = {
        "schemaVersion": 1,
        "catalogRevision": args.revision,
        "issuedAtEpochSeconds": now,
        "expiresAtEpochSeconds": now + args.validity_days * 24 * 3600,
        "channel": "stable",
        "trustedHosts": TRUSTED_HOSTS,
        "entries": entries,
    }
    payload_bytes = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as handle:
        handle.write(DOMAIN + payload_bytes)
        signed_path = handle.name
    try:
        signature = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", args.key, signed_path],
            check=True, capture_output=True,
        ).stdout
    finally:
        os.unlink(signed_path)

    envelope = {
        "envelopeVersion": 1,
        "algorithm": "ECDSA_P256_SHA256",
        "keyId": args.key_id,
        "payload": base64.b64encode(payload_bytes).decode("ascii"),
        "signature": base64.b64encode(signature).decode("ascii"),
    }

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(envelope, handle, ensure_ascii=False, separators=(",", ":"))
    print("目录已生成：rev %d，%d 条" % (args.revision, len(entries)))


if __name__ == "__main__":
    main()
