#!/usr/bin/env python3
"""Reject a rendered Paperless-ngx/RKE2 bundle missing essential production shape.

Usage: verify-paperless-rke2-model.py <approved-namespace> < rendered.yaml

This is a static preapply check for the selected Paperless-ngx v3.2.1 policy.
PostgreSQL may be external or in-cluster, and broker, ingress, and PVC providers
are not prescribed. The full Paperless container runs once with Recreate because
this contract has no verified multi-instance migration or worker-split design.
Explicit environment entries make required settings reviewable. Referenced
ConfigMap and Secret keys must be present in the render, and the application
secret key must pass a basic non-placeholder check. Unresolved replacement
markers are rejected in rendered text and base64 Secret data. Key entropy and
stability, broker URL behavior, and CA trust still require release and runtime
evidence. A PVC reference proves only the declared storage attachment, not
that the claim is Bound, durable, or backed up. Independent runtime tests in
the 100-point readiness contract remain required.
"""

from __future__ import annotations

import base64
import binascii
import posixpath
import re
import sys
from collections.abc import Hashable
from typing import Any
from urllib.parse import urlsplit

try:
    import yaml
except ImportError:  # Fail deterministically in an incomplete controller image.
    yaml = None  # type: ignore[assignment]


MAX_MODEL_BYTES = 16 * 1024 * 1024
MAX_DOCUMENTS = 1000
MAX_NODES = 100_000
MAX_DEPTH = 64
MAX_SECRET_VALUE_BYTES = 1024 * 1024
NAMESPACE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
IMAGE = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}\Z")
PLACEHOLDER = re.compile(r"example\.invalid|replace|todo|tbd|change-me|changeme", re.IGNORECASE)
UNRESOLVED_MARKER = re.compile(r"replace_with_", re.IGNORECASE)
PAPERLESS_NAME = "paperless-ngx"
DEFAULT_DATA_DIR = "/usr/src/paperless/data"
DEFAULT_MEDIA_ROOT = "/usr/src/paperless/media"
FORBIDDEN_AUTH_SETTINGS = frozenset({
    "PAPERLESS_AUTO_LOGIN_USERNAME",
    "PAPERLESS_ENABLE_HTTP_REMOTE_USER",
    "PAPERLESS_ENABLE_HTTP_REMOTE_USER_API",
})
REVIEWED_DIRECT_SETTINGS = frozenset({
    "PAPERLESS_SECRET_KEY", "PAPERLESS_REDIS",
    "PAPERLESS_DBENGINE", "PAPERLESS_DBHOST", "PAPERLESS_DBPORT",
    "PAPERLESS_DBNAME", "PAPERLESS_DBUSER", "PAPERLESS_DBPASS",
    "PAPERLESS_DB_OPTIONS", "PAPERLESS_URL", "PAPERLESS_DATA_DIR",
    "PAPERLESS_MEDIA_ROOT", "PAPERLESS_ADMIN_USER", "PAPERLESS_ADMIN_PASSWORD",
    "PAPERLESS_ADMIN_MAIL", "PAPERLESS_TIME_ZONE",
    "PAPERLESS_CONSUMER_POLLING_INTERVAL",
})
APPROVED_FILE_SETTINGS = frozenset({"PAPERLESS_SECRET_KEY_FILE", "PAPERLESS_REDIS_FILE"})


class InvalidInput(ValueError):
    """The invocation or rendered YAML is invalid (exit 2)."""


class ModelRejected(ValueError):
    """The rendered Paperless model misses a required property (exit 1)."""


def _decode_secret_data(value: Any) -> bytes:
    if not isinstance(value, str) or len(value) > MAX_SECRET_VALUE_BYTES * 2:
        raise ModelRejected("rendered Secret data is invalid or oversized")
    # Kubernetes's Go base64 decoder ignores CR/LF, and Kustomize wraps long
    # generated values. Retain strict validation for every other character.
    compact = value.replace("\r", "").replace("\n", "")
    try:
        decoded = base64.b64decode(compact, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ModelRejected("rendered Secret data is not valid base64") from exc
    if len(decoded) > MAX_SECRET_VALUE_BYTES:
        raise ModelRejected("rendered Secret data is oversized")
    return decoded


if yaml is not None:
    class _StrictLoader(yaml.SafeLoader):
        def compose_node(self, parent: Any, index: Any) -> Any:
            if self.check_event(yaml.AliasEvent):
                raise InvalidInput("rendered YAML must not contain aliases")
            return super().compose_node(parent, index)

        def construct_mapping(self, node: Any, deep: bool = False) -> dict[Hashable, Any]:
            if not isinstance(node, yaml.MappingNode):
                raise InvalidInput("rendered YAML has an invalid mapping")
            result: dict[Hashable, Any] = {}
            for key_node, value_node in node.value:
                key = self.construct_object(key_node, deep=deep)
                if not isinstance(key, str):
                    raise InvalidInput("rendered YAML has a non-string mapping key")
                if key in result:
                    raise InvalidInput("rendered YAML has duplicate mapping keys")
                result[key] = self.construct_object(value_node, deep=deep)
            return result


def _documents(raw: bytes) -> list[dict[str, Any]]:
    if yaml is None:
        raise InvalidInput("PyYAML is required in the controller execution environment")
    if not raw or len(raw) > MAX_MODEL_BYTES:
        raise InvalidInput("rendered model is empty or exceeds its size limit")
    try:
        result: list[dict[str, Any]] = []
        for document in yaml.load_all(raw.decode("utf-8", errors="strict"), Loader=_StrictLoader):
            if len(result) >= MAX_DOCUMENTS:
                raise InvalidInput("rendered model exceeds its document limit")
            if not isinstance(document, dict):
                raise InvalidInput("rendered model contains a non-object document")
            result.append(document)
    except (UnicodeDecodeError, yaml.YAMLError, RecursionError) as exc:
        raise InvalidInput("rendered model is not valid, bounded UTF-8 YAML") from exc
    if not result:
        raise InvalidInput("rendered model has no resources")
    pending: list[tuple[Any, int]] = [(item, 0) for item in result]
    visited = 0
    while pending:
        item, depth = pending.pop()
        visited += 1
        if visited > MAX_NODES or depth > MAX_DEPTH:
            raise InvalidInput("rendered model exceeds its structure limit")
        if isinstance(item, dict):
            pending.extend((value, depth + 1) for value in item.values())
            pending.extend((key, depth + 1) for key in item)
        elif isinstance(item, list):
            pending.extend((value, depth + 1) for value in item)
        elif isinstance(item, str) and UNRESOLVED_MARKER.search(item):
            raise ModelRejected("rendered model contains an unresolved replacement marker")
    for document in result:
        if document.get("kind") == "Secret" and document.get("apiVersion") == "v1":
            data = document.get("data", {})
            if not isinstance(data, dict):
                raise ModelRejected("rendered Secret data is invalid")
            for value in data.values():
                decoded = _decode_secret_data(value)
                if b"replace_with_" in decoded.lower():
                    raise ModelRejected("rendered Secret contains an unresolved replacement marker")
    return result


def _objects(documents: list[dict[str, Any]], namespace: str) -> dict[tuple[str, str], dict[str, Any]]:
    objects: dict[tuple[str, str], dict[str, Any]] = {}
    for document in documents:
        kind = document.get("kind")
        api_version = document.get("apiVersion")
        metadata = document.get("metadata")
        if (
            not isinstance(kind, str) or not kind
            or not isinstance(api_version, str) or not api_version
            or not isinstance(metadata, dict)
            or not isinstance(metadata.get("name"), str) or not metadata["name"]
        ):
            raise InvalidInput("rendered resource lacks Kubernetes identity")
        name = metadata["name"]
        actual_namespace = metadata.get("namespace")
        if kind == "Namespace":
            if api_version != "v1" or name != namespace or actual_namespace is not None:
                raise ModelRejected("rendered Namespace differs from the approved namespace")
        elif actual_namespace != namespace:
            raise ModelRejected("rendered resource is outside the approved namespace")
        key = (kind, name)
        if key in objects:
            raise InvalidInput("rendered model contains duplicate resource identities")
        objects[key] = document
    return objects


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ModelRejected(f"{label} is missing or invalid")
    return value


def _list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise ModelRejected(f"{label} is missing or invalid")
    return value


def _env(container: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if "envFrom" in container:
        raise ModelRejected("Paperless environment must not use unchecked envFrom sources")
    entries = _list(container.get("env"), "Paperless environment")
    result: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("name"), str) or not entry["name"]:
            raise ModelRejected("Paperless environment contains an invalid entry")
        name = entry["name"]
        if name in FORBIDDEN_AUTH_SETTINGS or (
            name.endswith("_FILE") and name[:-5] in FORBIDDEN_AUTH_SETTINGS
        ):
            raise ModelRejected("Paperless environment enables an unreviewed authentication path")
        if name in result or ("value" in entry and "valueFrom" in entry):
            raise ModelRejected("Paperless environment contains a duplicate or ambiguous entry")
        result[name] = entry
    for name in result:
        if name.endswith("_FILE") and name not in APPROVED_FILE_SETTINGS and (
            name[:-5] in REVIEWED_DIRECT_SETTINGS or name[:-5] in result
        ):
            raise ModelRejected("Paperless reviewed setting has an unchecked file override")
    return result


def _static_value(
    environment: dict[str, dict[str, Any]],
    name: str,
    objects: dict[tuple[str, str], dict[str, Any]],
    *,
    required: bool = True,
) -> str | None:
    entry = environment.get(name)
    if entry is None:
        if required:
            raise ModelRejected(f"Paperless setting {name} is absent")
        return None
    value = entry.get("value")
    if isinstance(value, str):
        return value
    reference = entry.get("valueFrom")
    if not isinstance(reference, dict) or set(reference) != {"configMapKeyRef"}:
        raise ModelRejected(f"Paperless setting {name} must have a reviewable value")
    key_ref = _mapping(reference["configMapKeyRef"], f"{name} ConfigMap reference")
    config_name = key_ref.get("name")
    key = key_ref.get("key")
    if (
        not isinstance(config_name, str) or not config_name
        or not isinstance(key, str) or not key
        or key_ref.get("optional", False) is not False
    ):
        raise ModelRejected(f"Paperless setting {name} has an invalid ConfigMap reference")
    config = objects.get(("ConfigMap", config_name))
    data = config.get("data") if isinstance(config, dict) else None
    value = data.get(key) if isinstance(data, dict) else None
    if not isinstance(value, str):
        raise ModelRejected(f"Paperless setting {name} cannot be resolved from the rendered ConfigMap")
    return value


def _secret_reference(entry: dict[str, Any], name: str) -> tuple[str, str]:
    reference = entry.get("valueFrom")
    if not isinstance(reference, dict) or set(reference) != {"secretKeyRef"}:
        raise ModelRejected(f"Paperless setting {name} must use a Kubernetes Secret key")
    key_ref = _mapping(reference["secretKeyRef"], f"{name} Secret reference")
    if (
        not isinstance(key_ref.get("name"), str) or not key_ref["name"]
        or not isinstance(key_ref.get("key"), str) or not key_ref["key"]
        or key_ref.get("optional", False) is not False
    ):
        raise ModelRejected(f"Paperless setting {name} has an invalid Secret reference")
    return key_ref["name"], key_ref["key"]


def _secret_material(
    objects: dict[tuple[str, str], dict[str, Any]], name: str, key: str, label: str
) -> bytes:
    secret = objects.get(("Secret", name))
    if not isinstance(secret, dict) or secret.get("apiVersion") != "v1":
        raise ModelRejected(f"{label} references a Secret absent from the rendered model")
    data = secret.get("data", {})
    string_data = secret.get("stringData", {})
    if not isinstance(data, dict) or not isinstance(string_data, dict) or (
        key in data and key in string_data
    ):
        raise ModelRejected(f"{label} references an ambiguous Secret key")
    if key in data:
        value = _decode_secret_data(data[key])
    elif key in string_data and isinstance(string_data[key], str):
        value = string_data[key].encode("utf-8")
    else:
        raise ModelRejected(f"{label} references a missing Secret key")
    if not value:
        raise ModelRejected(f"{label} references an empty Secret key")
    if len(value) > MAX_SECRET_VALUE_BYTES:
        raise ModelRejected(f"{label} references an oversized Secret key")
    return value


def _projected_key(source: dict[str, Any], relative_path: str, label: str) -> str:
    if relative_path in ("", ".") or relative_path.startswith("../"):
        raise ModelRejected(f"{label} has an invalid projected file path")
    items = source.get("items")
    if items is None:
        if "/" in relative_path:
            raise ModelRejected(f"{label} has no projected item for its file path")
        return relative_path
    if not isinstance(items, list):
        raise ModelRejected(f"{label} has invalid projected items")
    matches = [
        item.get("key") for item in items
        if isinstance(item, dict) and item.get("path") == relative_path
    ]
    if len(matches) != 1 or not isinstance(matches[0], str) or not matches[0]:
        raise ModelRejected(f"{label} has no unique projected key for its file path")
    return matches[0]


def _review_secret_references(
    environment: dict[str, dict[str, Any]], pod_spec: dict[str, Any],
    objects: dict[tuple[str, str], dict[str, Any]],
) -> None:
    for name, entry in environment.items():
        reference = entry.get("valueFrom")
        if isinstance(reference, dict) and "secretKeyRef" in reference:
            secret_name, key = _secret_reference(entry, name)
            _secret_material(objects, secret_name, key, f"Paperless setting {name}")
    for volume in _list(pod_spec.get("volumes"), "Paperless pod volumes"):
        if not isinstance(volume, dict):
            raise ModelRejected("Paperless pod has an invalid volume")
        source = volume.get("secret")
        if source is None:
            continue
        if not isinstance(source, dict) or not isinstance(source.get("secretName"), str):
            raise ModelRejected("Paperless pod has an invalid Secret volume")
        secret_name = source["secretName"]
        resource = objects.get(("Secret", secret_name))
        if not isinstance(resource, dict) or resource.get("apiVersion") != "v1":
            raise ModelRejected("Paperless pod references a Secret absent from the rendered model")
        items = source.get("items")
        if items is not None:
            if not isinstance(items, list) or not items:
                raise ModelRejected("Paperless pod Secret volume has invalid projected items")
            for item in items:
                if not isinstance(item, dict) or not isinstance(item.get("key"), str):
                    raise ModelRejected("Paperless pod Secret volume has an invalid projected key")
                _secret_material(objects, secret_name, item["key"], "Paperless pod Secret volume")


def _absolute_path(value: Any, label: str) -> str:
    if (
        not isinstance(value, str) or not value.startswith("/") or "\x00" in value
        or "//" in value or any(segment in ("", ".", "..") for segment in value.split("/")[1:-1])
        or PLACEHOLDER.search(value)
    ):
        raise ModelRejected(f"{label} must be a concrete absolute path")
    normalized = posixpath.normpath(value)
    if normalized == "/" or normalized != value.rstrip("/"):
        raise ModelRejected(f"{label} must be a normalized non-root path")
    return normalized


def _covering_mount(
    path: str, container: dict[str, Any], pod_spec: dict[str, Any], label: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    mounts = _list(container.get("volumeMounts"), "Paperless volume mounts")
    volumes = _list(pod_spec.get("volumes"), "Paperless pod volumes")
    volume_map: dict[str, dict[str, Any]] = {}
    for volume in volumes:
        if not isinstance(volume, dict) or not isinstance(volume.get("name"), str) or not volume["name"]:
            raise ModelRejected("Paperless pod has an invalid volume")
        if volume["name"] in volume_map:
            raise ModelRejected("Paperless pod has duplicate volume names")
        volume_map[volume["name"]] = volume
    matches: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
    for mount in mounts:
        if not isinstance(mount, dict):
            raise ModelRejected("Paperless pod has an invalid volume mount")
        mount_name = mount.get("name")
        mount_path = mount.get("mountPath")
        if not isinstance(mount_name, str) or mount_name not in volume_map:
            raise ModelRejected("Paperless pod mount has no matching volume")
        mount_path = _absolute_path(mount_path, "Paperless mount path")
        if path == mount_path or path.startswith(mount_path.rstrip("/") + "/"):
            matches.append((mount_path, mount, volume_map[mount_name]))
    if not matches:
        raise ModelRejected(f"{label} has no persistent mount")
    matches.sort(key=lambda row: len(row[0]), reverse=True)
    return matches[0][1], matches[0][2]


def _secret_file(
    environment: dict[str, dict[str, Any]], name: str,
    container: dict[str, Any], pod_spec: dict[str, Any],
    objects: dict[tuple[str, str], dict[str, Any]],
) -> bytes:
    entry = environment.get(name)
    if entry is None or not isinstance(entry.get("value"), str):
        raise ModelRejected(f"Paperless setting {name} must name a Secret-backed file")
    path = _absolute_path(entry["value"], name)
    mount, volume = _covering_mount(path, container, pod_spec, name)
    secret = volume.get("secret")
    if (
        path == mount["mountPath"].rstrip("/")
        or not isinstance(secret, dict)
        or not isinstance(secret.get("secretName"), str)
        or not secret["secretName"]
        or secret.get("optional", False) is not False
    ):
        raise ModelRejected(f"Paperless setting {name} is not backed by a required Secret")
    relative_path = posixpath.relpath(path, mount["mountPath"].rstrip("/"))
    key = _projected_key(secret, relative_path, f"Paperless setting {name}")
    return _secret_material(objects, secret["secretName"], key, f"Paperless setting {name}")


def _secret_key(
    environment: dict[str, dict[str, Any]], container: dict[str, Any], pod_spec: dict[str, Any],
    objects: dict[tuple[str, str], dict[str, Any]],
) -> None:
    direct = environment.get("PAPERLESS_SECRET_KEY")
    file = environment.get("PAPERLESS_SECRET_KEY_FILE")
    if (direct is None) == (file is None):
        raise ModelRejected("Paperless must have exactly one Secret-backed secret key source")
    if direct is not None:
        name, key = _secret_reference(direct, "PAPERLESS_SECRET_KEY")
        value = _secret_material(objects, name, key, "PAPERLESS_SECRET_KEY")
    else:
        value = _secret_file(environment, "PAPERLESS_SECRET_KEY_FILE", container, pod_spec, objects)
    try:
        value_text = value.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ModelRejected("PAPERLESS_SECRET_KEY must be a usable UTF-8 secret") from exc
    if (
        len(value) < 32 or len(value) > 4096 or len(set(value_text)) < 8
        or value_text != value_text.strip() or "\x00" in value_text
        or PLACEHOLDER.search(value_text)
    ):
        raise ModelRejected("PAPERLESS_SECRET_KEY is weak or a placeholder")


def _url(value: str, scheme: str, label: str, *, origin_only: bool) -> None:
    if not value or PLACEHOLDER.search(value) or any(character.isspace() for character in value):
        raise ModelRejected(f"{label} is empty or a placeholder")
    try:
        parsed = urlsplit(value)
        valid_port = parsed.port is None or 1 <= parsed.port <= 65535
    except ValueError as exc:
        raise ModelRejected(f"{label} has an invalid port or host") from exc
    if (
        parsed.scheme != scheme or not parsed.hostname or not valid_port
        or parsed.username is not None or parsed.password is not None
        or parsed.query or parsed.fragment
        or (origin_only and (parsed.path or value.endswith("/")))
        or (origin_only and parsed.hostname in {"localhost", "127.0.0.1", "::1"})
    ):
        raise ModelRejected(f"{label} is not an approved {scheme} URL")


def _broker(
    environment: dict[str, dict[str, Any]],
    container: dict[str, Any], pod_spec: dict[str, Any],
    objects: dict[tuple[str, str], dict[str, Any]],
) -> None:
    direct = environment.get("PAPERLESS_REDIS")
    file = environment.get("PAPERLESS_REDIS_FILE")
    if (direct is None) == (file is None):
        raise ModelRejected("Paperless must have exactly one explicit broker URL source")
    if file is not None:
        _secret_file(environment, "PAPERLESS_REDIS_FILE", container, pod_spec, objects)
        return
    assert direct is not None
    _secret_reference(direct, "PAPERLESS_REDIS")


def _persistent_directory(
    path: str, container: dict[str, Any], pod_spec: dict[str, Any], label: str
) -> None:
    mount, volume = _covering_mount(path, container, pod_spec, label)
    claim = volume.get("persistentVolumeClaim")
    if (
        mount.get("readOnly", False) is not False or not isinstance(claim, dict)
        or not isinstance(claim.get("claimName"), str) or not claim["claimName"]
        or PLACEHOLDER.search(claim["claimName"])
        or claim.get("readOnly", False) is not False
    ):
        raise ModelRejected(f"{label} is not backed by a writable PersistentVolumeClaim")


def _database_tls(
    environment: dict[str, dict[str, Any]],
    objects: dict[tuple[str, str], dict[str, Any]],
    container: dict[str, Any],
    pod_spec: dict[str, Any],
) -> None:
    if "PAPERLESS_DB_OPTIONS_FILE" in environment:
        raise ModelRejected("Paperless database TLS options must have a reviewable value")
    value = _static_value(environment, "PAPERLESS_DB_OPTIONS", objects)
    assert value is not None
    options: dict[str, str] = {}
    for option in value.split(","):
        key, separator, option_value = option.partition("=")
        if not separator or not key or not option_value or key != key.strip() or key in options:
            raise ModelRejected("Paperless database options are malformed or repeated")
        options[key] = option_value
    if options.get("sslmode") != "verify-full":
        raise ModelRejected("Paperless PostgreSQL connection must verify the server hostname")
    ca_path = _absolute_path(options.get("sslrootcert"), "PostgreSQL root CA path")
    if options["sslrootcert"] != ca_path:
        raise ModelRejected("PostgreSQL root CA path must name one exact file")
    mount, volume = _covering_mount(ca_path, container, pod_spec, "PostgreSQL root CA")
    if mount.get("readOnly") is not True or "subPath" in mount or "subPathExpr" in mount:
        raise ModelRejected("PostgreSQL root CA requires a read-only projected volume")
    mount_path = mount["mountPath"].rstrip("/")
    if ca_path == mount_path:
        raise ModelRejected("PostgreSQL root CA must be a file below its mount directory")
    secret = volume.get("secret")
    config = volume.get("configMap")
    if (isinstance(secret, dict)) == (isinstance(config, dict)):
        raise ModelRejected("PostgreSQL root CA must come from one Secret or ConfigMap")
    source = secret if isinstance(secret, dict) else config
    assert isinstance(source, dict)
    source_name = source.get("secretName") if secret is not None else source.get("name")
    if (
        not isinstance(source_name, str) or not source_name
        or source.get("optional", False) is not False
    ):
        raise ModelRejected("PostgreSQL root CA source must be required and named")
    relative_path = posixpath.relpath(ca_path, mount_path)
    key = _projected_key(source, relative_path, "PostgreSQL root CA")
    if isinstance(secret, dict):
        _secret_material(objects, source_name, key, "PostgreSQL root CA")
    else:
        config_map = objects.get(("ConfigMap", source_name))
        data = config_map.get("data", {}) if isinstance(config_map, dict) else None
        binary_data = config_map.get("binaryData", {}) if isinstance(config_map, dict) else None
        if (
            not isinstance(config_map, dict) or config_map.get("apiVersion") != "v1"
            or not isinstance(data, dict) or not isinstance(binary_data, dict)
            or (key not in data and key not in binary_data)
            or key in data and key in binary_data
            or key in data and (not isinstance(data[key], str) or not data[key])
            or key in binary_data and (not isinstance(binary_data[key], str) or not binary_data[key])
        ):
            raise ModelRejected("PostgreSQL root CA is absent from the rendered ConfigMap")
        if key in binary_data:
            _decode_secret_data(binary_data[key])


def _app_container(
    deployment: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any], dict[str, dict[str, Any]]]:
    spec = _mapping(deployment.get("spec"), "Paperless Deployment spec")
    if type(spec.get("replicas")) is not int or spec["replicas"] != 1:
        raise ModelRejected("Paperless full application requires exactly one explicit replica")
    strategy = _mapping(spec.get("strategy"), "Paperless Deployment strategy")
    if strategy.get("type") != "Recreate" or "rollingUpdate" in strategy:
        raise ModelRejected("Paperless full application requires a Recreate rollout")
    template = _mapping(spec.get("template"), "Paperless pod template")
    pod_spec = _mapping(template.get("spec"), "Paperless pod specification")
    containers = _list(pod_spec.get("containers"), "Paperless containers")
    candidates: list[tuple[dict[str, Any], dict[str, dict[str, Any]]]] = []
    for container in containers:
        if not isinstance(container, dict):
            raise ModelRejected("Paperless pod has an invalid container")
        names = {
            item["name"] for item in container.get("env", [])
            if isinstance(item, dict) and isinstance(item.get("name"), str)
        } if isinstance(container.get("env", []), list) else set()
        if names & {"PAPERLESS_SECRET_KEY", "PAPERLESS_SECRET_KEY_FILE"}:
            candidates.append((container, _env(container)))
    if len(candidates) != 1:
        raise ModelRejected("Paperless Deployment must have one identifiable full application container")
    return candidates[0][0], pod_spec, candidates[0][1]


def _port_and_service(
    app: dict[str, Any], deployment: dict[str, Any], objects: dict[tuple[str, str], dict[str, Any]]
) -> None:
    ports = _list(app.get("ports"), "Paperless container ports")
    names: set[str] = set()
    found = False
    for port in ports:
        if not isinstance(port, dict):
            raise ModelRejected("Paperless container has an invalid port")
        if port.get("containerPort") == 8000 and port.get("protocol", "TCP") == "TCP":
            found = True
            if isinstance(port.get("name"), str) and port["name"]:
                names.add(port["name"])
    if not found:
        raise ModelRejected("Paperless container must expose TCP port 8000")
    labels = _mapping(
        _mapping(_mapping(deployment["spec"]["template"], "Paperless pod template").get("metadata"),
                 "Paperless pod metadata").get("labels"),
        "Paperless pod labels",
    )
    if not labels:
        raise ModelRejected("Paperless pod has no Service-selectable labels")
    for (kind, _), service in objects.items():
        if kind != "Service":
            continue
        spec = service.get("spec")
        if not isinstance(spec, dict):
            continue
        selector = spec.get("selector")
        if not isinstance(selector, dict) or not selector or any(labels.get(k) != v for k, v in selector.items()):
            continue
        service_ports = spec.get("ports")
        if not isinstance(service_ports, list):
            continue
        for port in service_ports:
            if (
                isinstance(port, dict) and port.get("protocol", "TCP") == "TCP"
                and (
                    port.get("targetPort") == 8000
                    or (isinstance(port.get("targetPort"), str) and port["targetPort"] in names)
                )
            ):
                return
    raise ModelRejected("no reviewed Service routes to Paperless TCP port 8000")


def _single_full_application(
    app: dict[str, Any], objects: dict[tuple[str, str], dict[str, Any]]
) -> None:
    image = app.get("image")
    if not isinstance(image, str) or IMAGE.fullmatch(image) is None or PLACEHOLDER.search(image):
        raise ModelRejected("Paperless application image must be an immutable digest reference")
    image_repository = image.split("@", 1)[0]
    workload_kinds = {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob"}

    def paperless_labels(value: Any) -> bool:
        return isinstance(value, dict) and any(
            value.get(key) == PAPERLESS_NAME
            for key in ("app", "app.kubernetes.io/name", "k8s-app")
        )

    for (kind, name), resource in objects.items():
        if kind == "HorizontalPodAutoscaler":
            spec = resource.get("spec")
            target = spec.get("scaleTargetRef") if isinstance(spec, dict) else None
            if isinstance(target, dict) and target.get("kind") == "Deployment" and target.get("name") == PAPERLESS_NAME:
                raise ModelRejected("Paperless full application must not be autoscaled")
        if kind not in workload_kinds or (
            kind == "Deployment" and name == PAPERLESS_NAME
        ):
            continue
        metadata = resource.get("metadata")
        if name == PAPERLESS_NAME or paperless_labels(
            metadata.get("labels") if isinstance(metadata, dict) else None
        ):
            raise ModelRejected("another workload has Paperless application identity")
        spec = resource.get("spec")
        if kind == "CronJob" and isinstance(spec, dict):
            job_template = spec.get("jobTemplate")
            job_spec = job_template.get("spec") if isinstance(job_template, dict) else None
            template = job_spec.get("template") if isinstance(job_spec, dict) else None
        else:
            template = spec.get("template") if isinstance(spec, dict) else None
        template_metadata = template.get("metadata") if isinstance(template, dict) else None
        if paperless_labels(
            template_metadata.get("labels") if isinstance(template_metadata, dict) else None
        ):
            raise ModelRejected("another workload selects Paperless application pods")
        pod_spec = template.get("spec") if isinstance(template, dict) else None
        if not isinstance(pod_spec, dict):
            continue
        for container_group in ("containers", "initContainers"):
            containers = pod_spec.get(container_group)
            if not isinstance(containers, list):
                continue
            for container in containers:
                if not isinstance(container, dict):
                    continue
                candidate_image = container.get("image")
                candidate_repo = candidate_image.split("@", 1)[0] if isinstance(candidate_image, str) else None
                entries = container.get("env")
                app_environment = isinstance(entries, list) and any(
                    isinstance(entry, dict) and isinstance(entry.get("name"), str)
                    and entry["name"].startswith("PAPERLESS_")
                    for entry in entries
                )
                if (
                    container.get("name") == PAPERLESS_NAME
                    or candidate_repo in {image_repository, "ghcr.io/paperless-ngx/paperless-ngx"}
                    or app_environment
                ):
                    raise ModelRejected("another workload runs a Paperless application container")


def verify(raw: bytes, namespace: str) -> None:
    """Raise if the bounded rendered model lacks the selected release policy."""
    if not isinstance(namespace, str) or NAMESPACE.fullmatch(namespace) is None:
        raise InvalidInput("approved namespace is invalid")
    objects = _objects(_documents(raw), namespace)
    deployment = objects.get(("Deployment", PAPERLESS_NAME))
    if deployment is None or deployment.get("apiVersion") != "apps/v1":
        raise ModelRejected("rendered model lacks the named apps/v1 Paperless Deployment")
    app, pod_spec, environment = _app_container(deployment)
    _single_full_application(app, objects)
    _review_secret_references(environment, pod_spec, objects)
    _secret_key(environment, app, pod_spec, objects)
    engine = _static_value(environment, "PAPERLESS_DBENGINE", objects)
    if engine != "postgresql":
        raise ModelRejected("Paperless requires an explicit PostgreSQL database engine")
    host = _static_value(environment, "PAPERLESS_DBHOST", objects)
    if host is None or not host or PLACEHOLDER.search(host):
        raise ModelRejected("Paperless requires a concrete PostgreSQL host")
    db_password = environment.get("PAPERLESS_DBPASS")
    if db_password is None or "PAPERLESS_DBPASS_FILE" in environment:
        raise ModelRejected("Paperless PostgreSQL password must use one required Secret key")
    _secret_reference(db_password, "PAPERLESS_DBPASS")
    _database_tls(environment, objects, app, pod_spec)
    _broker(environment, app, pod_spec, objects)
    public_url = _static_value(environment, "PAPERLESS_URL", objects)
    assert public_url is not None
    _url(public_url, "https", "PAPERLESS_URL", origin_only=True)
    if "PAPERLESS_ADMIN_PASSWORD" in environment:
        _secret_reference(environment["PAPERLESS_ADMIN_PASSWORD"], "PAPERLESS_ADMIN_PASSWORD")
    data_dir = _static_value(environment, "PAPERLESS_DATA_DIR", objects, required=False) or DEFAULT_DATA_DIR
    media_root = _static_value(environment, "PAPERLESS_MEDIA_ROOT", objects, required=False) or DEFAULT_MEDIA_ROOT
    _persistent_directory(_absolute_path(data_dir, "PAPERLESS_DATA_DIR"), app, pod_spec, "Paperless data")
    _persistent_directory(_absolute_path(media_root, "PAPERLESS_MEDIA_ROOT"), app, pod_spec, "Paperless media")
    _port_and_service(app, deployment, objects)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: verify-paperless-rke2-model.py <approved-namespace> < rendered.yaml", file=sys.stderr)
        return 2
    raw = sys.stdin.buffer.read(MAX_MODEL_BYTES + 1)
    try:
        verify(raw, argv[1])
    except InvalidInput as exc:
        print(f"Paperless rendered model input invalid: {exc}", file=sys.stderr)
        return 2
    except (ModelRejected, RecursionError) as exc:
        print(f"Paperless rendered model rejected: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
