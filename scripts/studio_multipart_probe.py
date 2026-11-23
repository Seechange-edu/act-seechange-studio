"""Run a multipart qualification against the standby container's S3 identity."""

import base64
from contextlib import closing
import hashlib
import json
import os
import re
import sys
from types import SimpleNamespace
from urllib.request import urlopen


MIB = 1024 * 1024
PART_BYTES = 32 * MIB
PREFIX = "studio-storage"


def aws_code(error):
    return getattr(error, "response", {}).get("Error", {}).get("Code")


def validate_request(bucket, encoded):
    if not re.fullmatch(r"seechange-video-studio-prod-[0-9]{12}-ap-east-1-an", bucket):
        raise ValueError("Expected a dedicated Hong Kong Studio bucket.")
    request = json.loads(base64.b64decode(encoded, validate=True))
    if not isinstance(request, dict):
        raise ValueError("Expected an object.")
    op = request.get("op")
    size = request.get("bytes")
    if (op not in ("sign", "complete", "abort") or type(size) is not int
            or not 100 * MIB <= size <= 1024 * MIB
            or not re.fullmatch(r"[a-f0-9]{32}", request.get("nonce", ""))
            or not re.fullmatch(r"[a-f0-9]{64}", request.get("sha256", ""))):
        raise ValueError("Invalid qualification request.")
    checksums = request.get("checksums")
    expected_parts = (size + PART_BYTES - 1) // PART_BYTES
    if not isinstance(checksums, list) or len(checksums) != expected_parts:
        raise ValueError("Invalid part checksum list.")
    for checksum in checksums:
        if not isinstance(checksum, str) or len(checksum) != 44:
            raise ValueError("Invalid part checksum.")
        raw = base64.b64decode(checksum, validate=True)
        if len(raw) != 32 or base64.b64encode(raw).decode("ascii") != checksum:
            raise ValueError("Invalid part checksum.")
    upload_id = request.get("upload_id")
    if upload_id is not None or op != "sign":
        if (not isinstance(upload_id, str) or not 1 <= len(upload_id) <= 2048
                or not upload_id.isascii() or not upload_id.isprintable() or " " in upload_id):
            raise ValueError("Invalid multipart upload ID.")
    if op == "complete":
        etags = request.get("etags")
        if not isinstance(etags, list) or len(etags) != expected_parts or any(
            not isinstance(tag, str) or not 1 <= len(tag) <= 256
            or not tag.isascii() or not tag.isprintable() for tag in etags
        ):
            raise ValueError("Invalid part ETag list.")
    return request


def part_bytes(total, number):
    return min(PART_BYTES, total - (number - 1) * PART_BYTES)


def sign(client, target, request):
    upload_id = request.get("upload_id")
    if upload_id is None:
        created = client.create_multipart_upload(
            **target, ChecksumAlgorithm="SHA256", ChecksumType="COMPOSITE",
            ContentType="video/mp4", Metadata={"sha256": request["sha256"]},
        )
        upload_id = created["UploadId"]
    grants = []
    for number, checksum in enumerate(request["checksums"], 1):
        size = part_bytes(request["bytes"], number)
        url = client.generate_presigned_url(
            "upload_part", Params={**target, "UploadId": upload_id, "PartNumber": number,
                                   "ContentLength": size, "ChecksumSHA256": checksum},
            ExpiresIn=3600,
        )
        grants.append({"number": number, "url": url, "bytes": size, "sha256": checksum})
    return {"upload_id": upload_id, "grants": grants, "key": target["Key"]}


def verify_version(client, target, request, head, list_parts_allowed):
    version = head.get("VersionId")
    if (not version or version == "null" or head.get("ContentLength") != request["bytes"]
            or head.get("ContentType") != "video/mp4"
            or head.get("Metadata", {}).get("sha256") != request["sha256"]
            or head.get("ChecksumType") != "COMPOSITE" or not head.get("ChecksumSHA256")):
        raise ValueError("Invalid completed object metadata.")
    response = client.get_object(**target, VersionId=version)
    digest = hashlib.sha256()
    size = 0
    with closing(response["Body"]) as body:
        if response.get("VersionId") != version:
            raise ValueError("S3 returned a different object version.")
        for chunk in iter(lambda: body.read(1024 * 1024), b""):
            size += len(chunk)
            if size > request["bytes"]:
                raise ValueError("S3 returned an oversized object.")
            digest.update(chunk)
    if size != request["bytes"] or digest.hexdigest() != request["sha256"]:
        raise ValueError("The exact S3 version did not match the original.")
    return {"key": target["Key"], "version_id": version, "bytes": size, "sha256": digest.hexdigest(),
            "checksum_match": True, "list_parts_allowed": list_parts_allowed}


def complete(client, target, request):
    upload_id = request["upload_id"]
    parts = [{"PartNumber": number, "ETag": etag, "ChecksumSHA256": checksum}
             for number, (etag, checksum) in enumerate(zip(request["etags"], request["checksums"]), 1)]
    list_parts_allowed = True
    try:
        listed = client.list_parts(**target, UploadId=upload_id)
    except Exception as error:
        code = aws_code(error)
        if code == "NoSuchUpload":
            head = client.head_object(**target, ChecksumMode="ENABLED")
            return verify_version(client, target, request, head, list_parts_allowed)
        if code not in ("AccessDenied", "403"):
            raise
        list_parts_allowed = False
    else:
        expected = [{**part, "Size": part_bytes(request["bytes"], part["PartNumber"])} for part in parts]
        actual = [{field: part.get(field) for field in ("PartNumber", "ETag", "ChecksumSHA256", "Size")}
                  for part in listed.get("Parts", [])]
        if listed.get("IsTruncated") or actual != expected:
            raise ValueError("S3 parts differ from the submitted upload receipts.")
    try:
        completed = client.complete_multipart_upload(
            **target, UploadId=upload_id, MultipartUpload={"Parts": parts},
        )
    except Exception as error:
        if aws_code(error) != "NoSuchUpload":
            raise
        head = client.head_object(**target, ChecksumMode="ENABLED")
    else:
        version = completed.get("VersionId")
        if not version or version == "null":
            raise ValueError("S3 returned no usable version.")
        head = client.head_object(**target, VersionId=version, ChecksumMode="ENABLED")
        if head.get("VersionId") != version:
            raise ValueError("S3 returned a different object version.")
    return verify_version(client, target, request, head, list_parts_allowed)


def abort(client, target, request):
    try:
        client.abort_multipart_upload(**target, UploadId=request["upload_id"])
    except Exception as error:
        if aws_code(error) != "NoSuchUpload":
            raise
    return {"key": target["Key"], "aborted": True}


def main():
    stage = "request"
    try:
        bucket, encoded = sys.argv[1:]
        request = validate_request(bucket, encoded)
        stage = "standby"
        with urlopen("http://127.0.0.1:8080/readyz", timeout=5) as response:
            readiness = json.load(response)
        if readiness.get("dispatch_enabled") is not False or readiness.get("cutover_ready") is not False:
            raise ValueError("Expected dispatch and cutover disabled.")

        stage = "runtime_profile"
        from studio_control.ssm_secrets import load_profile_env
        from studio_control.storage import Storage

        load_profile_env()
        settings = SimpleNamespace(bucket=bucket, region="ap-east-1", prefix=PREFIX)
        if os.environ.get("STUDIO_S3_ACCESS_KEY_PARAMETER") or os.environ.get("STUDIO_S3_SECRET_KEY_PARAMETER"):
            from studio_control.ssm_secrets import load_s3_credentials
            storage = Storage(settings, credentials=load_s3_credentials())
        else:
            storage = Storage(settings)
        client = storage.client()
        stage = "bucket_versioning"
        if client.get_bucket_versioning(Bucket=bucket).get("Status") != "Enabled":
            raise ValueError("Expected bucket versioning enabled.")

        stage = request["op"]
        target = {"Bucket": bucket, "Key": f"{PREFIX}/private/qualification/multipart-{request['nonce']}.mp4"}
        operation = {"sign": sign, "complete": complete, "abort": abort}[stage]
        print(json.dumps(operation(client, target, request)), flush=True)
        return 0
    except Exception as error:
        code = type(error).__name__
        while error is not None:
            if service_code := aws_code(error):
                code = service_code
                break
            error = error.__cause__ or error.__context__
        print(json.dumps({"stage": stage, "error": code}), flush=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
