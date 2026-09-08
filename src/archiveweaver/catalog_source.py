"""Authoritative catalog source for ArchiveWeaver.

This file deliberately keeps product facts separate from the execution engine.
The generated JSON files are the runtime contract consumed by the CLI.
"""

from __future__ import annotations

from copy import deepcopy


MODES = [
    "raw",
    "docker",
    "k3s",
    "rke2",
    "pacemaker",
    "podman-quadlet",
    "k0s",
    "docker-swarm",
    "microk8s",
    "ansible",
]

CONTAINER_MODES = [
    "docker",
    "k3s",
    "rke2",
    "podman-quadlet",
    "k0s",
    "docker-swarm",
    "microk8s",
]


OPERATING_SYSTEMS = [
    {"id": "ubuntu-22.04", "name": "Ubuntu 22.04 LTS", "family": "debian", "tier": "validated-base"},
    {"id": "ubuntu-24.04", "name": "Ubuntu 24.04 LTS", "family": "debian", "tier": "preferred"},
    {"id": "ubuntu-26.04", "name": "Ubuntu 26.04 LTS", "family": "debian", "tier": "forward-validate"},
    {"id": "rocky-8", "name": "Rocky Linux 8", "family": "el", "tier": "legacy-conditional"},
    {"id": "rocky-9", "name": "Rocky Linux 9", "family": "el", "tier": "preferred"},
    {"id": "rocky-10", "name": "Rocky Linux 10", "family": "el", "tier": "forward-validate"},
    {"id": "rhel-8", "name": "Red Hat Enterprise Linux 8", "family": "el", "tier": "legacy-conditional"},
    {"id": "rhel-9", "name": "Red Hat Enterprise Linux 9", "family": "el", "tier": "validated-base"},
    {"id": "rhel-10", "name": "Red Hat Enterprise Linux 10", "family": "el", "tier": "forward-validate"},
    {"id": "alma-8", "name": "AlmaLinux 8", "family": "el", "tier": "legacy-conditional"},
    {"id": "alma-9", "name": "AlmaLinux 9", "family": "el", "tier": "validated-base"},
    {"id": "alma-10", "name": "AlmaLinux 10", "family": "el", "tier": "forward-validate"},
    {"id": "debian-12", "name": "Debian 12", "family": "debian", "tier": "validated-base"},
    {"id": "debian-13", "name": "Debian 13", "family": "debian", "tier": "validated-base"},
]


RUNTIMES = [
    {
        "id": "raw",
        "name": "Raw / native installation",
        "kind": "native",
        "topology": {"1": "supported", "2": "conditional", "3": "conditional", "3+": "conditional"},
        "prerequisites": ["systemd", "package manager", "TLS termination", "external backup"],
        "notes": "Use the upstream installation method. HA depends on whether the product supports clustering and on externalizing state.",
    },
    {
        "id": "docker",
        "name": "Docker Compose",
        "kind": "container",
        "topology": {"1": "supported", "2": "conditional", "3": "conditional", "3+": "conditional"},
        "prerequisites": ["Docker Engine", "Docker Compose v2", "persistent volumes", "external backup"],
        "notes": "Compose is a packaging format, not a multi-host consensus system. Use Swarm or Kubernetes for multi-host scheduling.",
    },
    {
        "id": "k3s",
        "name": "K3s",
        "kind": "kubernetes",
        "topology": {"1": "supported", "2": "not-recommended", "3": "supported", "3+": "supported"},
        "prerequisites": ["3 or 5 server nodes for embedded-etcd HA", "CNI", "Ingress", "CSI-backed storage", "external object storage"],
        "notes": "Two embedded-etcd servers do not provide a resilient quorum. Three or more server nodes are the baseline.",
    },
    {
        "id": "rke2",
        "name": "RKE2",
        "kind": "kubernetes",
        "topology": {"1": "supported", "2": "not-recommended", "3": "supported", "3+": "supported"},
        "prerequisites": ["3 server nodes for embedded-etcd HA", "CNI", "Ingress", "CSI-backed storage", "external object storage"],
        "notes": "RKE2 server nodes are schedulable by default; separate agent nodes when workload isolation is required.",
    },
    {
        "id": "pacemaker",
        "name": "Pacemaker / Corosync + STONITH",
        "kind": "cluster-manager",
        "topology": {"1": "supported", "2": "supported-with-stonith", "3": "supported", "3+": "supported"},
        "prerequisites": ["Corosync", "Pacemaker", "pcs", "tested STONITH device", "quorum or qdevice", "shared or replicated storage"],
        "notes": "Best for active/passive systemd services and VIPs. Do not use it to fake active/active application clustering.",
    },
    {
        "id": "podman-quadlet",
        "name": "Podman Quadlet",
        "kind": "container",
        "topology": {"1": "supported", "2": "conditional", "3": "conditional", "3+": "conditional"},
        "prerequisites": ["Podman 4.4+", "systemd", "persistent volumes", "external backup"],
        "notes": "Quadlet is a systemd-integrated single-host lifecycle mechanism. Pair it with Pacemaker for active/passive failover.",
    },
    {
        "id": "k0s",
        "name": "k0s",
        "kind": "kubernetes",
        "topology": {"1": "supported", "2": "not-recommended", "3": "supported", "3+": "supported"},
        "prerequisites": ["3 or 5 controller nodes for etcd HA", "CNI", "Ingress", "CSI-backed storage", "external object storage"],
        "notes": "Use controllers with etcd for HA; use workers for workload isolation and a control-plane load balancer.",
    },
    {
        "id": "docker-swarm",
        "name": "Docker Swarm",
        "kind": "container-orchestrator",
        "topology": {"1": "supported", "2": "not-recommended", "3": "supported", "3+": "supported"},
        "prerequisites": ["3 or 5 manager nodes for Raft quorum", "overlay network", "shared or replicated storage", "external backup"],
        "notes": "Run an odd number of managers. Two managers cannot tolerate a manager failure while preserving quorum.",
    },
    {
        "id": "microk8s",
        "name": "MicroK8s",
        "kind": "kubernetes",
        "topology": {"1": "supported", "2": "not-recommended", "3": "supported", "3+": "supported"},
        "prerequisites": ["3 or 5 control-plane nodes for datastore HA", "CNI", "Ingress", "CSI-backed storage", "external object storage"],
        "notes": "The datastore must itself be highly available; use three or more control-plane nodes for production.",
    },
    {
        "id": "ansible",
        "name": "Ansible orchestration adapter",
        "kind": "automation",
        "topology": {"1": "supported", "2": "supported", "3": "supported", "3+": "supported"},
        "prerequisites": [
            "pinned Ansible Core execution environment",
            "SSH with host-key verification",
            "Python 3 on managed nodes",
            "reviewed become policy",
            "version-controlled inventory and group variables",
            "Ansible Vault or an approved external secret manager",
            "an underlying raw, container, cluster, or Pacemaker runtime",
            "external backup and restore evidence",
        ],
        "notes": "Ansible is an orchestration and configuration-management layer, not a scheduler or HA system. Use it to coordinate the existing provider envelopes; quorum, fencing, state replication, and application support remain the responsibility of the selected underlying runtime and product release.",
    },
]


FORMATS = {
    "documents": {
        "label": "Documents",
        "extensions": "pdf,doc,docx,odt,ott,rtf,txt,md,tex,wpd,pages,xps,oxps",
        "mime_examples": "application/pdf,application/msword,application/vnd.openxmlformats-officedocument.wordprocessingml.document,text/plain,text/markdown",
    },
    "spreadsheets": {
        "label": "Spreadsheets and tabular data",
        "extensions": "xls,xlsx,ods,ots,csv,tsv,xml,json,parquet,feather,sav,dta",
        "mime_examples": "text/csv,application/vnd.ms-excel,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet,application/json",
    },
    "presentations": {
        "label": "Presentations",
        "extensions": "ppt,pptx,odp,otp,key",
        "mime_examples": "application/vnd.ms-powerpoint,application/vnd.openxmlformats-officedocument.presentationml.presentation",
    },
    "images": {
        "label": "Images and raster graphics",
        "extensions": "jpg,jpeg,jpe,png,gif,bmp,tif,tiff,jp2,j2k,jpf,jpx,jpm,mj2,webp,avif,heic,heif,svg,eps,psd,ico,raw,dng,cr2,cr3,nef,nrw,arw,orf,rw2,raf,pef,sr2,3fr,iiq",
        "mime_examples": "image/jpeg,image/png,image/tiff,image/jp2,image/svg+xml,image/webp,image/heic",
    },
    "audio": {
        "label": "Audio",
        "extensions": "wav,mp3,flac,ogg,oga,opus,m4a,aac,wma,aiff,aif,alac,ape,amr,midi,mid",
        "mime_examples": "audio/wav,audio/mpeg,audio/flac,audio/ogg,audio/mp4,audio/aac",
    },
    "video": {
        "label": "Video",
        "extensions": "mp4,m4v,mov,avi,mkv,webm,ogv,mpg,mpeg,mpe,wmv,flv,asf,3gp,3g2,mxf,mts,m2ts,ts,vob",
        "mime_examples": "video/mp4,video/quicktime,video/x-msvideo,video/x-matroska,video/webm",
    },
    "ebooks": {
        "label": "E-books and page-description formats",
        "extensions": "epub,epub3,mobi,azw,azw3,fb2,djvu,cbr,cbz",
        "mime_examples": "application/epub+zip,application/x-mobipocket-ebook,image/vnd.djvu",
    },
    "archives": {
        "label": "Archives and disk/container files",
        "extensions": "zip,7z,rar,tar,gz,tgz,bz2,xz,z,br,iso,ova,ovf,vhd,vhdx,vmdk",
        "mime_examples": "application/zip,application/x-7z-compressed,application/gzip,application/x-tar",
    },
    "email": {
        "label": "E-mail and messaging exports",
        "extensions": "eml,msg,mbox,pst,ost,emlx,ics,vcf",
        "mime_examples": "message/rfc822,application/vnd.ms-outlook,application/mbox,text/calendar,text/vcard",
    },
    "web": {
        "label": "Web and markup",
        "extensions": "html,htm,xhtml,css,js,ts,jsx,tsx,wasm,xml,json,yaml,yml,ttl,rdf,n3,nq,trig,nt",
        "mime_examples": "text/html,application/xhtml+xml,application/xml,application/json,text/turtle",
    },
    "scientific": {
        "label": "Scientific, research and geospatial data",
        "extensions": "hdf,hdf5,netcdf,nc,mat,fits,fits.gz,fastq,fasta,fa,geojson,gpkg,kml,kmz,shp,shx,dbf,prj,las,laz,dcm,dicom",
        "mime_examples": "application/x-hdf,application/netcdf,application/geo+json,application/dicom",
    },
    "structured": {
        "label": "Databases, logs and machine-readable exports",
        "extensions": "sql,sqlite,sqlite3,db,db3,log,ndjson,txt,bin,dat",
        "mime_examples": "application/sql,application/x-sqlite3,text/plain,application/octet-stream",
    },
    "fonts": {
        "label": "Fonts",
        "extensions": "ttf,otf,woff,woff2",
        "mime_examples": "font/ttf,font/otf,font/woff,font/woff2",
    },
    "preservation": {
        "label": "Preservation packages and fixity sidecars",
        "extensions": "bagit,bag,md5,sha1,sha256,sha512,xml,mets,premis,sip,aip,dip,war,jar",
        "mime_examples": "application/xml,application/war,application/java-archive,application/octet-stream",
    },
}


def _modes(raw: str = "native", docker: str = "validated") -> dict[str, str]:
    support = {mode: "portable" for mode in MODES}
    support["raw"] = raw
    support["docker"] = docker
    support["pacemaker"] = "conditional"
    support["ansible"] = "portable"
    return support


def _health(service_aliases: list[str], paths: list[str] | None = None, port: int | None = 80) -> dict:
    return {
        "service_aliases": service_aliases,
        "http_paths": paths or ["/"],
        "default_port": port,
        "checks": ["process-or-service", "http", "storage-paths", "dependency-reachability", "configuration-presence"],
    }


def _solution(
    id: str,
    name: str,
    category: str,
    repo: str,
    docs: str,
    homepage: str,
    license: str,
    architecture: list[str],
    formats: list[str],
    dependencies: list[str],
    services: list[str],
    raw: str = "native",
    docker: str = "validated",
    source_repo: str | None = None,
    notes: list[str] | None = None,
    paths: list[str] | None = None,
    port: int = 80,
    image_hint: str | None = None,
) -> dict:
    return {
        "id": id,
        "name": name,
        "category": category,
        "upstream_repo": repo,
        "source_repo": source_repo or repo,
        "official_docs": docs,
        "homepage": homepage,
        "license": license,
        "architecture_components": architecture,
        "format_profiles": formats,
        "dependencies": dependencies,
        "health": _health(services, paths, port),
        "mode_support": _modes(raw, docker),
        "notes": notes or [],
        "image_hint": image_hint,
    }


SOLUTIONS = [
    _solution("invenio-rdm", "InvenioRDM", "research-data-management", "https://github.com/inveniosoftware/invenio-rdm", "https://inveniordm.docs.cern.ch/install/", "https://inveniosoftware.org/products/rdm/", "MIT", ["Invenio application", "PostgreSQL", "OpenSearch/Elasticsearch", "Redis", "RabbitMQ", "S3-compatible object storage"], ["documents", "spreadsheets", "presentations", "images", "audio", "video", "ebooks", "archives", "scientific", "structured"], ["Python", "PostgreSQL", "Redis", "OpenSearch/Elasticsearch", "RabbitMQ", "S3"], ["invenio", "nginx", "gunicorn"], notes=["Treat the application as a distributed service; keep object storage and database outside the web process."]),
    _solution("dspace", "DSpace", "institutional-repository", "https://github.com/DSpace/DSpace", "https://wiki.lyrasis.org/display/DSDOC10x/Installing+DSpace", "https://dspace.org/", "BSD-3-Clause", ["DSpace backend", "DSpace Angular UI", "PostgreSQL", "Solr", "Tomcat", "S3-compatible storage"], ["documents", "spreadsheets", "presentations", "images", "audio", "video", "ebooks", "archives", "scientific", "structured"], ["Java", "Maven", "Ant", "PostgreSQL", "Solr", "Tomcat"], ["dspace", "tomcat", "solr"], paths=["/server/api", "/home"]),
    _solution("archivematica", "Archivematica", "digital-preservation", "https://github.com/artefactual/archivematica", "https://www.archivematica.org/en/docs/archivematica-latest/admin-manual/installation-setup/", "https://www.archivematica.org/", "AGPL-3.0", ["Archivematica dashboard", "Storage Service", "MCP server", "MCP client", "PostgreSQL", "Elasticsearch", "RabbitMQ", "Gearman", "Bag/S3 storage"], ["documents", "images", "audio", "video", "ebooks", "archives", "email", "web", "scientific", "preservation"], ["Python", "PostgreSQL", "Elasticsearch", "RabbitMQ", "Gearman", "FPR tools", "S3/NFS"], ["archivematica", "archivematica-storage-service", "nginx"], notes=["Preservation workflows are multi-service; a single container health check is not enough."]),
    _solution("dataverse", "Dataverse", "research-data-management", "https://github.com/IQSS/dataverse", "https://guides.dataverse.org/en/latest/installation/", "https://dataverse.org/", "Apache-2.0", ["Dataverse web application", "Payara", "PostgreSQL", "Solr", "S3/file storage", "SMTP"], ["documents", "spreadsheets", "presentations", "images", "audio", "video", "archives", "scientific", "structured"], ["Java", "Payara", "PostgreSQL", "Solr", "S3", "SMTP"], ["dataverse", "payara", "solr"], paths=["/api/info/version"], port=8080),
    _solution("islandora", "Islandora", "digital-asset-management", "https://github.com/Islandora/islandora", "https://islandora.github.io/documentation/installation/", "https://islandora.ca/", "GPL-3.0", ["Drupal", "Islandora modules", "Fedora", "Solr", "Alpaca/Media", "Redis", "database", "object storage"], ["documents", "images", "audio", "video", "ebooks", "archives", "web", "scientific", "preservation"], ["PHP", "Drupal", "Fedora", "Solr", "Redis", "MariaDB/PostgreSQL"], ["apache2", "httpd", "nginx", "fedora", "solr"], docker="validated", notes=["Islandora is a framework/distribution; deployment must choose a Drupal/Fedora composition such as the official documentation path."]),
    _solution("mayan-edms", "Mayan EDMS", "document-management", "https://github.com/mayan-edms/Mayan-EDMS", "https://docs.mayan-edms.com/parts/installation.html", "https://www.mayan-edms.com/", "Apache-2.0", ["Django web", "Celery workers", "PostgreSQL", "Redis", "Elasticsearch/OpenSearch", "S3/file storage"], ["documents", "images", "audio", "video", "archives", "email", "structured"], ["Python", "Django", "PostgreSQL", "Redis", "Celery", "OCR tools"], ["mayan", "celery", "redis", "postgresql"], source_repo="https://gitlab.com/mayan-edms/mayan-edms", image_hint="mayanedms/mayanedms"),
    _solution("fedora-repository", "Fedora Repository", "repository-backend", "https://github.com/fcrepo/fcrepo", "https://wiki.lyrasis.org/display/FEDORA6x/Installation+and+Configuration", "https://fedorarepository.org/", "Apache-2.0", ["Fedora REST API", "Spring Boot", "Java", "PostgreSQL/JDBC", "binary storage", "messaging/integration"], ["documents", "images", "audio", "video", "ebooks", "archives", "web", "scientific", "structured", "preservation"], ["Java", "Maven", "Servlet/container", "database", "object/filesystem storage"], ["fedora", "tomcat", "java"], port=8080, notes=["Fedora is a repository backend, not a complete public UI; pair it with a client such as Islandora or Hyrax."]),
    _solution("samvera-hyrax", "Samvera Hyrax", "repository-application-framework", "https://github.com/samvera/hyrax", "https://samvera.org/get-started/getting-started", "https://hyrax.samvera.org/", "Apache-2.0", ["Rails host application", "Hyrax engine", "Solr", "Fedora/ActiveFedora", "Redis", "PostgreSQL", "S3 storage"], ["documents", "spreadsheets", "presentations", "images", "audio", "video", "ebooks", "archives", "scientific", "structured", "preservation"], ["Ruby", "Rails", "Solr", "PostgreSQL", "Redis", "Fedora or ActiveFedora", "S3"], ["hyrax", "puma", "solr", "redis"], port=3000, notes=["Hyrax is a Rails engine and must be mounted in a host application; it is not a standalone web app."]),
    _solution("roda-community", "RODA Community", "digital-preservation", "https://github.com/keeps/roda", "https://www.roda-community.org/documentation/", "https://www.roda-community.org/", "LGPL-3.0", ["RODA web application", "RODA-in", "Java", "PostgreSQL", "Solr", "object storage", "preservation plugins"], ["documents", "images", "audio", "video", "ebooks", "archives", "email", "web", "scientific", "preservation"], ["Java", "Maven", "PostgreSQL", "Solr", "S3/filesystem", "JDK tools"], ["roda", "tomcat", "solr"], notes=["The upstream local installation guide is single-node and testing-oriented; design production storage and database separately."]),
    _solution("maarch-rm", "Maarch RM", "electronic-records-management", "https://labs.maarch.org/maarch/maarchRM", "https://docs.maarch.org/gitbook/html/maarchRM/", "https://maarch.com/maarch-rm/", "GPL-3.0", ["Maarch RM", "PHP web", "PostgreSQL", "Apache", "Docker image", "archive storage"], ["documents", "images", "audio", "video", "email", "archives", "preservation"], ["PHP", "Apache", "PostgreSQL", "Java", "ImageMagick", "Ghostscript", "P7Zip"], ["apache2", "httpd", "postgresql"], source_repo="https://labs.maarch.org/maarch/maarchRM", image_hint="maarch/maarchrm", notes=["The official project is hosted on Maarch Labs rather than GitHub; use the linked documentation and image registry."]),
    _solution("asalae", "Asalae", "digital-preservation", "https://gitlab.adullact.net/Libriciel/archivage/asalae", "https://www.asalae.fr/", "https://www.asalae.fr/", "AGPL-3.0", ["Asalae web", "worker/queue", "PostgreSQL", "Elasticsearch", "S3/filesystem storage", "Docker Compose"], ["documents", "images", "audio", "video", "archives", "email", "web", "scientific", "preservation"], ["PHP/Python", "PostgreSQL", "Elasticsearch", "Redis or queue", "S3/filesystem"], ["asalae", "apache2", "nginx", "postgresql"], docker="validated", notes=["The official source and Compose assets are hosted on the ADULLACT GitLab instance."]),
    _solution("resourcespace", "ResourceSpace", "digital-asset-management", "https://github.com/resourcespace/resourcespace", "https://www.resourcespace.com/knowledge-base/systemadmin/install_overview", "https://www.resourcespace.com/", "BSD-3-Clause", ["PHP web", "MySQL/MariaDB", "ImageMagick", "FFmpeg", "file storage", "optional search/preview services"], ["images", "audio", "video", "documents", "archives", "fonts"], ["PHP", "Apache/Nginx", "MySQL/MariaDB", "ImageMagick", "FFmpeg", "ExifTool"], ["apache2", "httpd", "nginx", "mariadb", "mysql"], image_hint="resourcespace/resourcespace", notes=["Large media uploads require deliberate PHP, web-server, reverse-proxy, and filesystem limits."]),
    _solution("maarch-courrier", "Maarch Courrier", "mail-management", "https://labs.maarch.org/maarch/MaarchCourrier", "https://docs.maarch.org/", "https://maarch.com/maarch-courrier/", "GPL-3.0", ["Maarch Courrier", "PHP web", "PostgreSQL", "Apache", "mail/notification services", "Docker image"], ["documents", "images", "email", "archives", "structured"], ["PHP", "Apache", "PostgreSQL", "Java", "ImageMagick", "Ghostscript"], ["apache2", "httpd", "postgresql"], source_repo="https://labs.maarch.org/maarch/MaarchCourrier", image_hint="maarch/maarchcourrier", notes=["Use the official Maarch Labs source and the current Maarch documentation; older GitHub mirrors are not authoritative."]),
    _solution("docspell", "Docspell", "document-management", "https://github.com/eikek/docspell", "https://docspell.org/docs/", "https://docspell.org/", "GPL-3.0", ["Docspell restserver", "Joex workers", "PostgreSQL", "Solr", "Tika", "OCR tools", "file storage"], ["documents", "images", "email", "archives", "structured"], ["JVM", "PostgreSQL", "Solr", "Tika", "Tesseract", "OCRmyPDF", "S3/filesystem"], ["docspell", "solr", "postgresql"], port=7880, notes=["The project provides Docker Compose and Helm paths; the Debian package and Helm chart are better baselines than ad-hoc source builds."]),
    _solution("nextcloud-server", "Nextcloud Server", "file-sync-and-share", "https://github.com/nextcloud/server", "https://docs.nextcloud.com/server/latest/admin_manual/installation/", "https://nextcloud.com/", "AGPL-3.0", ["PHP web", "database", "Redis", "background jobs", "object storage", "preview/Office services"], ["documents", "spreadsheets", "presentations", "images", "audio", "video", "ebooks", "archives", "email", "web", "scientific", "structured", "fonts"], ["PHP", "Apache/Nginx", "MariaDB/PostgreSQL", "Redis", "cron", "TLS"], ["apache2", "httpd", "nginx", "php-fpm", "redis", "mariadb", "mysql"], notes=["Use external database, Redis locking, shared or object-backed data, and a separate preview/Office strategy for HA."]),
    _solution("archivesspace", "ArchivesSpace", "archival-description", "https://github.com/archivesspace/archivesspace", "https://docs.archivesspace.org/administration/getting_started/", "https://archivesspace.org/", "EPL-2.0", ["ArchivesSpace backend", "staff interface", "public interface", "MySQL/MariaDB", "Solr", "JRuby", "Docker"], ["documents", "images", "audio", "video", "ebooks", "archives", "structured"], ["JRuby/Java", "MySQL/MariaDB", "Solr", "Nginx/Apache", "Docker"], ["archivesspace", "solr", "mysql", "mariadb"], port=8089, notes=["The current technical documentation recommends Docker for new installations and documents clustering separately."]),
    _solution("atom", "AtoM (Access to Memory)", "archival-description", "https://github.com/artefactual/atom", "https://www.accesstomemory.org/docs/", "https://www.accesstomemory.org/", "AGPL-3.0", ["Symfony/PHP web", "MySQL/MariaDB", "Elasticsearch", "Gearman", "Qubit", "file storage"], ["documents", "images", "audio", "video", "archives", "email", "structured"], ["PHP", "Symfony", "MySQL/MariaDB", "Elasticsearch", "Gearman", "ImageMagick", "FFmpeg"], ["apache2", "httpd", "nginx", "elasticsearch", "mysql", "mariadb"], image_hint="artefactual/atom", notes=["AtoM has official tarball, source, and Docker guidance; Elasticsearch compatibility must follow the selected AtoM release."]),
    _solution("alfresco-community", "Alfresco Community Edition", "enterprise-content-management", "https://github.com/Alfresco/alfresco-community-repo", "https://docs.hyland.com/r/Alfresco/Alfresco-Content-Services-Community-Edition/23.3/Alfresco-Content-Services-Community-Edition/Install/Overview", "https://www.alfresco.com/", "LGPL-3.0", ["Repository", "Share/UI", "Search/Solr", "PostgreSQL", "ActiveMQ", "Transform Service", "S3/filesystem storage"], ["documents", "spreadsheets", "presentations", "images", "audio", "video", "ebooks", "archives", "email", "web", "structured"], ["Java", "Tomcat", "PostgreSQL", "Solr", "ActiveMQ", "Transform services", "Docker/Compose"], ["alfresco", "tomcat", "solr", "postgresql", "activemq"], port=8080, image_hint="alfresco/alfresco-content-repository-community", notes=["Alfresco Community is a multi-module platform; deploy the repository, search, Share, transforms, database, and messaging as a tested release set."]),
    _solution("eprints", "EPrints", "institutional-repository", "https://github.com/eprints/eprints3.4", "https://wiki.eprints.org/w/Installation", "https://www.eprints.org/", "GPL-3.0", ["EPrints core", "Perl", "Apache", "MySQL/MariaDB", "indexer", "file storage"], ["documents", "spreadsheets", "presentations", "images", "audio", "video", "ebooks", "archives", "structured"], ["Perl", "Apache", "MySQL/MariaDB", "XML/XSLT", "ImageMagick", "Ghostscript"], ["apache2", "httpd", "mysql", "mariadb", "eprints"], notes=["The official wiki distinguishes Debian/Ubuntu and RHEL/Fedora/CentOS installation paths; source Git is the production recommendation."]),
    _solution("kitodo-production", "Kitodo.Production", "digitization-workflow", "https://github.com/kitodo/kitodo-production", "https://www.kitodo.org/en/software/kitodoproduction", "https://www.kitodo.org/", "GPL-3.0", ["Kitodo web app", "Java/Tomcat", "MySQL/MariaDB", "Solr/Elasticsearch", "Goobi/Kitodo scripts", "METS/MODS files"], ["documents", "images", "archives", "web", "structured", "preservation"], ["Java", "Tomcat", "MySQL/MariaDB", "Solr/Elasticsearch", "ImageMagick", "OCR tools"], ["kitodo", "tomcat", "mysql", "mariadb", "solr"], port=8080, notes=["Version 4 changes the Java/Tomcat baseline; pin the server version to the selected Kitodo release."]),
    _solution("goobi-workflow", "Goobi workflow", "digitization-workflow", "https://github.com/intranda/goobi-workflow", "https://docs.goobi.io/en/other/vocabulary/general/installation", "https://goobi.io/", "GPL-2.0", ["Goobi workflow", "Java/Tomcat", "MySQL/MariaDB", "Solr", "workflow plugins", "file storage"], ["documents", "images", "archives", "web", "structured", "preservation"], ["Java", "Tomcat", "MySQL/MariaDB", "Solr", "ImageMagick", "OCR tools"], ["goobi", "tomcat", "mysql", "mariadb", "solr"], port=8080, notes=["Goobi uses a plugin ecosystem; application, plugin, and database versions must be released as one compatibility set."]),
    _solution("collectiveaccess", "CollectiveAccess Providence", "collections-management", "https://github.com/collectiveaccess/providence", "https://docs.collectiveaccess.org/providence/user/setup/install/", "https://collectiveaccess.org/", "GPL-3.0", ["Providence", "Pawtucket", "PHP", "MySQL/MariaDB", "media derivatives", "IIIF integrations"], ["documents", "images", "audio", "video", "ebooks", "archives", "web", "structured"], ["PHP", "Apache/Nginx", "MySQL/MariaDB", "ImageMagick", "FFmpeg", "ExifTool"], ["apache2", "httpd", "nginx", "mysql", "mariadb"], notes=["Providence is the cataloguing application; Pawtucket is the public web layer and should be versioned separately."]),
    _solution("seeddms", "SeedDMS", "document-management", "https://sourceforge.net/projects/seeddms/", "https://www.seeddms.org/", "https://www.seeddms.org/", "GPL-2.0", ["PHP web", "MySQL/MariaDB or SQLite", "file storage", "full-text/index plugins"], ["documents", "images", "archives", "email", "structured"], ["PHP", "Apache/Nginx", "MySQL/MariaDB", "PEAR", "optional OCR/index tools"], ["apache2", "httpd", "nginx", "mysql", "mariadb"], docker="conditional", notes=["The official download channel is SourceForge; GitHub mirrors are not treated as authoritative."]),
    _solution("paperless-ngx", "Paperless-ngx", "document-management", "https://github.com/paperless-ngx/paperless-ngx", "https://docs.paperless-ngx.com/setup/", "https://docs.paperless-ngx.com/", "GPL-3.0", ["Django web", "Celery workers", "PostgreSQL", "Redis", "Tika/Gotenberg", "OCRmyPDF/Tesseract", "media storage"], ["documents", "images", "email", "archives", "structured"], ["Python", "PostgreSQL", "Redis", "Tesseract", "OCRmyPDF", "Ghostscript", "Gotenberg", "Tika"], ["paperless", "celery", "redis", "postgresql"], image_hint="paperlessngx/paperless-ngx"),
    _solution("omeka-s", "Omeka S", "digital-publishing", "https://github.com/omeka/omeka-s", "https://omeka.org/s/docs/user-manual/install/", "https://omeka.org/s/", "GPL-3.0", ["PHP web", "MySQL/MariaDB", "Omeka modules", "themes", "IIIF/media services", "file storage"], ["documents", "images", "audio", "video", "ebooks", "archives", "web", "structured"], ["PHP", "Apache/Nginx", "MySQL/MariaDB", "ImageMagick", "FFmpeg", "ExifTool"], ["apache2", "httpd", "nginx", "mysql", "mariadb"], notes=["Omeka S is intentionally extensible through modules; check module compatibility as part of the release manifest."]),
    _solution("papermerge", "Papermerge DMS", "document-management", "https://github.com/papermerge/papermerge-core", "https://docs.papermerge.io/", "https://papermerge.com/", "Apache-2.0", ["Django/FastAPI services", "PostgreSQL", "Redis", "OCR", "Celery", "file storage"], ["documents", "images", "archives", "email", "structured"], ["Python", "PostgreSQL", "Redis", "Tesseract", "OCRmyPDF", "S3/filesystem"], ["papermerge", "celery", "redis", "postgresql"], image_hint="papermerge/papermerge"),
    _solution("openkm-community", "OpenKM Community", "document-management", "https://github.com/openkm/document-management-system", "https://docs.openkm.com/kcenter/", "https://www.openkm.com/", "GPL-2.0", ["OpenKM web", "Java/Tomcat", "database", "Lucene", "file storage", "workflow"], ["documents", "images", "audio", "video", "archives", "email", "structured"], ["Java", "Tomcat", "database", "Tesseract", "ImageMagick", "OpenOffice/LibreOffice"], ["openkm", "tomcat", "mysql", "mariadb"], port=8080, docker="conditional", notes=["The official GitHub repository is archived as of 2026; treat this adapter as maintenance-only and pin an audited release."]),
    _solution("teedy", "Teedy", "document-management", "https://github.com/sismics/docs", "https://teedy.io/en/", "https://teedy.io/", "GPL-2.0", ["Java web app", "Jetty", "H2/PostgreSQL", "Lucene", "Tesseract", "FFmpeg", "file storage"], ["documents", "images", "audio", "video", "archives", "email", "structured"], ["Java", "Maven", "Jetty/Tomcat", "Tesseract", "FFmpeg", "MediaInfo", "database"], ["teedy", "jetty", "tomcat"], port=8080, image_hint="sismics/teedy", notes=["Teedy was formerly known as Sismics Docs; pin the source/release identity and avoid community images unless explicitly approved."]),
    _solution("logicaldoc-community", "LogicalDOC Community", "document-management", "https://github.com/logicaldoc/community", "https://www.logicaldoc.com/download-logicaldoc-community", "https://www.logicaldoc.com/", "LGPL-3.0", ["Java web app", "Tomcat", "database", "Lucene", "OCR", "file storage"], ["documents", "images", "audio", "video", "archives", "email", "structured"], ["Java", "Tomcat", "MariaDB/MySQL", "HSQLDB for demo", "Tesseract", "LibreOffice"], ["logicaldoc", "tomcat", "mysql", "mariadb"], port=8080, image_hint="logicaldoc/logicaldoc-ce", notes=["The project publishes separate Community and Docker repositories; do not use embedded HSQLDB for production."]),
    _solution("seafile-community", "Seafile Community", "file-sync-and-share", "https://github.com/haiwen/seafile", "https://manual.seafile.com/", "https://www.seafile.com/", "AGPL-3.0", ["Seafile server", "Seahub", "MariaDB", "Memcached/Redis", "Nginx", "file libraries", "object storage"], ["documents", "spreadsheets", "presentations", "images", "audio", "video", "ebooks", "archives", "email", "web", "scientific", "structured", "fonts"], ["Seafile server", "Python", "MariaDB", "Memcached", "Nginx", "Docker"], ["seafile", "seahub", "nginx", "mariadb", "memcached"], raw="conditional", docker="validated", notes=["Current Community deployment guidance is container-first; verify the selected release's Community/Professional boundaries before applying HA automation."]),
]


def catalog() -> dict:
    return {
        "schema_version": 1,
        "generated_by": "scripts/generate_catalog.py",
        "modes": deepcopy(MODES),
        "operating_systems": deepcopy(OPERATING_SYSTEMS),
        "runtimes": deepcopy(RUNTIMES),
        "formats": deepcopy(FORMATS),
        "solutions": deepcopy(SOLUTIONS),
    }
