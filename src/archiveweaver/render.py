from __future__ import annotations

import json
import re
from textwrap import dedent, indent
from typing import Any

from .catalog import Catalog
from .planner import build_plan


_IMAGE_REFERENCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@:-]*$")
_IMAGE_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def _safe_image(image: str, allow_floating: bool) -> str:
    original = image
    image = image.strip()
    if not image or image != original:
        raise ValueError("an image reference is required for container rendering")
    if not _IMAGE_REFERENCE_RE.fullmatch(image) or image.count("@") > 1:
        raise ValueError("image references may contain only safe OCI characters")
    name, separator, digest = image.partition("@")
    if separator:
        if not name or not _IMAGE_DIGEST_RE.fullmatch(digest):
            raise ValueError("image digests must use sha256:<64 hex>")
    elif image.startswith((".", "/", ":", "@")) or image.endswith((".", "/", ":", "@")):
        raise ValueError("image reference has an unsafe boundary")
    if not allow_floating and not separator:
        raise ValueError(
            "mutable image references are blocked; provide an OCI sha256 digest or pass --allow-floating for non-production use"
        )
    return image


def render_docker(solution_id: str, image: str, port: int) -> str:
    return dedent(f"""
        # ArchiveWeaver deployment envelope for {solution_id}
        # Pin ARCHIVEWEAVER_SOLUTION_IMAGE to an approved OCI digest before use.
        services:
          app:
            image: {image}
            restart: unless-stopped
            init: true
            ports:
              - "${{ARCHIVEWEAVER_BIND_IP:-127.0.0.1}}:${{ARCHIVEWEAVER_PORT:-{port}}}:{port}"
            environment:
              ARCHIVEWEAVER_SOLUTION_ID: {solution_id}
            volumes:
              - ./data:/var/lib/archiveweaver/solution
            security_opt:
              - no-new-privileges:true
            cap_drop:
              - ALL
        # This envelope does not create a database, search engine, queue, or
        # object store. Add the product's official dependency stack separately.
    """).lstrip()


def render_kubernetes(solution_id: str, image: str, port: int, namespace: str, replicas: int) -> str:
    return dedent(f"""
        # ArchiveWeaver deployment envelope for {solution_id}
        # Replace the image with a pinned, approved OCI digest before applying.
        apiVersion: v1
        kind: Namespace
        metadata:
          name: {namespace}
        ---
        apiVersion: v1
        kind: PersistentVolumeClaim
        metadata:
          name: {solution_id}-data
          namespace: {namespace}
        spec:
          accessModes: ["ReadWriteMany"]
          resources:
            requests:
              storage: 100Gi
          storageClassName: ${{ARCHIVEWEAVER_STORAGE_CLASS}}
        ---
        apiVersion: apps/v1
        kind: Deployment
        metadata:
          name: {solution_id}
          namespace: {namespace}
          labels:
            app.kubernetes.io/name: {solution_id}
            app.kubernetes.io/managed-by: archiveweaver
        spec:
          replicas: {replicas}
          strategy:
            type: RollingUpdate
          selector:
            matchLabels:
              app.kubernetes.io/name: {solution_id}
          template:
            metadata:
              labels:
                app.kubernetes.io/name: {solution_id}
            spec:
              securityContext:
                seccompProfile:
                  type: RuntimeDefault
              affinity:
                podAntiAffinity:
                  preferredDuringSchedulingIgnoredDuringExecution:
                    - weight: 100
                      podAffinityTerm:
                        topologyKey: kubernetes.io/hostname
                        labelSelector:
                          matchLabels:
                            app.kubernetes.io/name: {solution_id}
              containers:
                - name: app
                  image: {image}
                  ports:
                    - name: http
                      containerPort: {port}
                  env:
                    - name: ARCHIVEWEAVER_SOLUTION_ID
                      value: {solution_id}
                  volumeMounts:
                    - name: data
                      mountPath: /var/lib/archiveweaver/solution
                  securityContext:
                    allowPrivilegeEscalation: false
                    capabilities:
                      drop: ["ALL"]
              volumes:
                - name: data
                  persistentVolumeClaim:
                    claimName: {solution_id}-data
        ---
        apiVersion: v1
        kind: Service
        metadata:
          name: {solution_id}
          namespace: {namespace}
        spec:
          selector:
            app.kubernetes.io/name: {solution_id}
          ports:
            - name: http
              port: 80
              targetPort: {port}
        # This envelope does not create the product database, search, queue,
        # object store, or ingress TLS policy. Add official dependencies first.
    """).lstrip()


def render_quadlet(solution_id: str, image: str, port: int) -> str:
    return dedent(f"""
        # /etc/containers/systemd/{solution_id}.container
        # Pin Image= to an approved OCI digest before use.
        [Unit]
        Description=ArchiveWeaver envelope for {solution_id}
        Wants=network-online.target
        After=network-online.target

        [Container]
        Image={image}
        ContainerName={solution_id}
        PublishPort=127.0.0.1:{port}:{port}
        Volume=%S/archiveweaver/{solution_id}:/var/lib/archiveweaver/solution:Z
        Environment=ARCHIVEWEAVER_SOLUTION_ID={solution_id}
        NoNewPrivileges=true

        [Service]
        Restart=always
        TimeoutStartSec=120

        [Install]
        WantedBy=multi-user.target

        # This is a single-host systemd envelope. Pair with Pacemaker only for
        # an explicitly reviewed active/passive design with STONITH.
    """).lstrip()


def render_swarm(
    solution_id: str,
    image: str,
    port: int,
    replicas: int,
    external_storage: bool,
) -> str:
    service = dedent(f"""
        # ArchiveWeaver deployment envelope for Docker Swarm
        version: "3.9"
        services:
          app:
            image: {image}
            ports:
              - target: {port}
                published: {port}
                protocol: tcp
                mode: ingress
            environment:
              ARCHIVEWEAVER_SOLUTION_ID: {solution_id}
            volumes:
              - archiveweaver_{solution_id}_data:/var/lib/archiveweaver/solution
            deploy:
              replicas: {replicas}
              update_config:
                order: start-first
                parallelism: 1
              restart_policy:
                condition: on-failure
              placement:
                max_replicas_per_node: 1
    """).lstrip()
    if external_storage:
        storage = dedent(f"""
        volumes:
          archiveweaver_{solution_id}_data:
            external: true
            name: "${{ARCHIVEWEAVER_DATA_VOLUME:?set a reviewed distributed volume name}}"
        # The external volume must use a tested shared or replicated storage
        # implementation and have independently verified restore evidence.
        """)
    else:
        storage = dedent(f"""
        volumes:
          archiveweaver_{solution_id}_data:
            driver: local
        # This local volume is valid only for a single-node deployment.
        """)
    return service + storage.lstrip()


def render_raw(solution_id: str, command: str) -> str:
    return dedent(f"""
        # /etc/systemd/system/{solution_id}.service
        # Replace ExecStart with the upstream product command and keep the
        # application data outside the unit file.
        [Unit]
        Description=ArchiveWeaver raw-install envelope for {solution_id}
        Wants=network-online.target
        After=network-online.target

        [Service]
        Type=simple
        User=archiveweaver
        Group=archiveweaver
        ExecStart={command}
        Restart=on-failure
        RestartSec=5
        NoNewPrivileges=true
        PrivateTmp=true
        ProtectSystem=strict
        ProtectHome=true
        ReadWritePaths=/var/lib/{solution_id} /var/log/{solution_id}

        [Install]
        WantedBy=multi-user.target
    """).lstrip()


def _yaml_string(value: str) -> str:
    """Emit a JSON-quoted scalar, which is also a valid YAML string."""
    return json.dumps(str(value), ensure_ascii=False)


def render_ansible(
    solution_id: str,
    nodes: str,
    os_id: str,
    namespace: str,
    port: int,
    underlying_mode: str = "raw",
    image: str = "",
    external_storage: bool = False,
) -> str:
    image_value = _yaml_string(image) if image else '""'
    common_vars = dedent(f"""
        archiveweaver_solution_id: {_yaml_string(solution_id)}
        archiveweaver_nodes: {_yaml_string(nodes)}
        archiveweaver_os_id: {_yaml_string(os_id)}
        archiveweaver_namespace: {_yaml_string(namespace)}
        archiveweaver_app_port: {port}
        archiveweaver_ansible_core_version: "2.21.4"
        archiveweaver_ansible_lint_version: "26.8.0"
        archiveweaver_ansible_runner_version: "2.4.3"
        archiveweaver_execution_environment_digest: ""
        archiveweaver_environment: "production"
        archiveweaver_evidence_environment: "production"
        archiveweaver_runtime: {_yaml_string(underlying_mode)}
        archiveweaver_image: {image_value}
        archiveweaver_external_storage_ready: {str(external_storage).lower()}
        archiveweaver_release: "REPLACE_WITH_PINNED_RELEASE"
        archiveweaver_change_id: "CHG-REPLACE"
        archiveweaver_operator: ""
        archiveweaver_fixture_set: ""
        # Bind the staged provider bundle to the reviewed release before
        # enabling apply. Use a bare SHA-256 hex digest here.
        archiveweaver_provider_bundle_sha256: ""
        archiveweaver_product_stack_sha256: ""
        archiveweaver_kustomize_bundle_sha256: ""
        archiveweaver_apply: false
        archiveweaver_run_verification: false
    """).strip()
    rendered_vars = indent(common_vars, "            ")
    return dedent(f"""
        ---
        # ArchiveWeaver generated Ansible entry point for {solution_id}
        #
        # This generated file is a review artifact. Production controller and
        # CLI operations use the fixed approved playbooks through
        # scripts/run-ansible-operational.sh; do not invoke this path directly
        # for a production mutation.
        # Run this file from deploy/ansible so the checked-in roles are on the
        # configured roles_path. It is an orchestration envelope, not a
        # universal product installer. Add the upstream product stack and
        # release-specific tasks only after staging validation.
        - name: Validate the pinned Ansible controller
          hosts: localhost
          connection: local
          gather_facts: false
          vars:
            archiveweaver_controller_target_group: archiveweaver_nodes
{rendered_vars}
          pre_tasks:
            - name: Preserve the post-play evidence sealing decision
              ansible.builtin.set_fact:
                archiveweaver_evidence_seal_enabled: "{{{{ archiveweaver_run_verification | default(false) | bool }}}}"
          roles:
            - role: archiveweaver_controller_preflight
              tags: [always, controller]

        - name: ArchiveWeaver enterprise deployment envelope
          hosts: archiveweaver_nodes
          become: true
          gather_facts: true
          serial: 1
          any_errors_fatal: true
          vars:
{rendered_vars}
          roles:
            - role: archiveweaver_preflight
              tags: [preflight]
            - role: archiveweaver_host
              when: archiveweaver_apply | bool
              tags: [host, deploy]
            - role: archiveweaver_provider
              when: archiveweaver_apply | bool
              tags: [provider, deploy]
            - role: archiveweaver_verify
              when: archiveweaver_run_verification | bool
              tags: [verify]

        - name: Seal ArchiveWeaver evidence after all managed hosts complete
          hosts: localhost
          connection: local
          gather_facts: false
          vars:
{rendered_vars}
            archiveweaver_evidence_completion_fact: archiveweaver_verify_completed
            archiveweaver_evidence_completion_hosts: "{{{{ groups['archiveweaver_nodes'] | default([]) }}}}"
          roles:
            - role: archiveweaver_evidence
              when: archiveweaver_evidence_seal_enabled | default(false) | bool
              tags: [evidence]
    """).lstrip()


def render(
    catalog: Catalog,
    solution_id: str,
    mode: str,
    nodes: str,
    os_id: str,
    *,
    namespace: str = "archiveweaver",
    image: str | None = None,
    allow_floating: bool = False,
    allow_conditional: bool = False,
    external_storage: bool = False,
    underlying_mode: str | None = None,
) -> tuple[dict[str, Any], str]:
    if mode != "ansible" and underlying_mode is not None:
        raise ValueError("--underlying-mode is only valid when --mode ansible is selected")
    selected_underlying_mode = underlying_mode or "raw"
    plan = build_plan(
        catalog,
        solution_id,
        mode,
        nodes,
        os_id,
        namespace=namespace,
        allow_conditional=allow_conditional,
        external_storage=external_storage,
        underlying_mode=selected_underlying_mode if mode == "ansible" else None,
    )
    if plan.status == "blocked":
        raise ValueError("render blocked: " + " ".join(plan.blockers))
    solution = catalog.solution(solution_id)
    runtime = catalog.runtime(mode)
    selected_image = image or solution.get("image_hint")
    if mode == "raw":
        command = "/usr/local/lib/archiveweaver/replace-with-upstream-command"
        return plan.as_dict(), render_raw(solution_id, command)
    if mode == "ansible":
        if selected_underlying_mode == "ansible":
            raise ValueError("Ansible cannot be its own underlying runtime")
        catalog.runtime(selected_underlying_mode)
        selected_image = _safe_image(image, allow_floating) if image else ""
        port = int(solution["health"]["default_port"] or 8080)
        return plan.as_dict(), render_ansible(
            solution_id,
            nodes,
            os_id,
            namespace,
            port,
            selected_underlying_mode,
            selected_image,
            external_storage,
        )
    selected_image = _safe_image(selected_image or "", allow_floating)
    port = int(solution["health"]["default_port"] or 8080)
    try:
        replica_count = max(1, int(nodes))
    except ValueError:
        replica_count = 3
    if mode == "docker":
        content = render_docker(solution_id, selected_image, port)
    elif mode == "podman-quadlet":
        content = render_quadlet(solution_id, selected_image, port)
    elif mode == "docker-swarm":
        content = render_swarm(
            solution_id,
            selected_image,
            port,
            replica_count,
            external_storage,
        )
    elif runtime["kind"] == "kubernetes":
        content = render_kubernetes(solution_id, selected_image, port, namespace, replica_count)
    else:
        raise ValueError(f"mode '{mode}' does not have a renderer; use the documented Pacemaker resource template")
    return plan.as_dict(), content
