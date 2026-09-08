from __future__ import annotations

from textwrap import dedent

from .catalog import Catalog
from .planner import build_plan


def _safe_image(image: str, allow_floating: bool) -> str:
    image = image.strip()
    if not image:
        raise ValueError("an image reference is required for container rendering")
    if not allow_floating:
        last_component = image.rsplit("/", 1)[-1]
        has_digest = "@sha256:" in image
        has_tag = ":" in last_component
        if not has_digest and not has_tag:
            raise ValueError("untagged image references are blocked; provide an immutable tag or digest, or pass --allow-floating")
        if image.endswith(":latest") or image in {"latest", "busybox", "nginx"}:
            raise ValueError("floating image tags are blocked; provide an immutable tag or digest, or pass --allow-floating")
    return image


def render_docker(solution_id: str, image: str, port: int) -> str:
    return dedent(f"""
        # ArchiveWeaver deployment envelope for {solution_id}
        # Pin ARCHIVEWEAVER_SOLUTION_IMAGE to a release tag or digest before use.
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
        # Replace the image with a pinned, approved release before applying.
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
        # Pin Image= to an approved release tag or digest before use.
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


def render_swarm(solution_id: str, image: str, port: int, replicas: int) -> str:
    return dedent(f"""
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
        volumes:
          archiveweaver_{solution_id}_data:
            driver: local
        # A local volume is not shared across hosts. Replace it with a tested
        # distributed storage driver and deploy official dependencies separately.
    """).lstrip()


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
) -> tuple[dict, str]:
    plan = build_plan(catalog, solution_id, mode, nodes, os_id, namespace=namespace, allow_conditional=allow_conditional)
    if plan.status == "blocked":
        raise ValueError("render blocked: " + " ".join(plan.blockers))
    solution = catalog.solution(solution_id)
    runtime = catalog.runtime(mode)
    selected_image = image or solution.get("image_hint")
    if mode == "raw":
        command = "/usr/local/lib/archiveweaver/replace-with-upstream-command"
        return plan.as_dict(), render_raw(solution_id, command)
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
        content = render_swarm(solution_id, selected_image, port, replica_count)
    elif runtime["kind"] == "kubernetes":
        content = render_kubernetes(solution_id, selected_image, port, namespace, replica_count)
    else:
        raise ValueError(f"mode '{mode}' does not have a renderer; use the documented Pacemaker resource template")
    return plan.as_dict(), content
