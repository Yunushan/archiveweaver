# Kitodo.Production

ArchiveWeaver adapter facts for planning, checking and repair. Product behavior remains governed by the upstream release documentation.

- **Category:** digitization-workflow
- **License:** GPL-3.0
- **Upstream repository:** https://github.com/kitodo/kitodo-production
- **Canonical source repository:** https://github.com/kitodo/kitodo-production
- **Official documentation:** https://www.kitodo.org/en/software/kitodoproduction
- **Homepage:** https://www.kitodo.org/
- **Default HTTP port:** 8080
- **Container image hint:** `No image pinned; use the upstream release or approved internal registry.`

## Architecture components

- Kitodo web app
- Java/Tomcat
- MySQL/MariaDB
- Solr/Elasticsearch
- Goobi/Kitodo scripts
- METS/MODS files

## Dependencies

- Java
- Tomcat
- MySQL/MariaDB
- Solr/Elasticsearch
- ImageMagick
- OCR tools

## Mode and topology matrix

| Mode | Product fit | 1 node | 2 nodes | 3 nodes | 3+ nodes |
| --- | --- | --- | --- | --- | --- |
| Raw / native installation | native | supported | conditional | conditional | conditional |
| Docker Compose | validated | supported | conditional | conditional | conditional |
| K3s | portable | supported | not-recommended | supported | supported |
| RKE2 | portable | supported | not-recommended | supported | supported |
| Pacemaker / Corosync + STONITH | conditional | supported | supported-with-stonith | supported | supported |
| Podman Quadlet | portable | supported | conditional | conditional | conditional |
| k0s | portable | supported | not-recommended | supported | supported |
| Docker Swarm | portable | supported | not-recommended | supported | supported |
| MicroK8s | portable | supported | not-recommended | supported | supported |
| Ansible orchestration adapter | portable | supported | supported | supported | supported |

`native` and `validated` refer to an upstream or repository-backed path. `portable` means ArchiveWeaver can render and check the runtime pattern, but the product's own HA guarantees and state model must be validated. `conditional` requires an explicit design review. `not-recommended` is intentionally blocked by the planner unless an exception is documented.

## Health checks

- `process-or-service`
- `http`
- `storage-paths`
- `dependency-reachability`
- `configuration-presence`

Service aliases: `kitodo, tomcat, mysql, mariadb, solr`

HTTP paths: `/`

## Format families

| Family | Extensions in the ArchiveWeaver catalog |
| --- | --- |
| Documents | pdf,doc,docx,odt,ott,rtf,txt,md,tex,wpd,pages,xps,oxps |
| Images and raster graphics | jpg,jpeg,jpe,png,gif,bmp,tif,tiff,jp2,j2k,jpf,jpx,jpm,mj2,webp,avif,heic,heif,svg,eps,psd,ico,raw,dng,cr2,cr3,nef,nrw,arw,orf,rw2,raf,pef,sr2,3fr,iiq |
| Archives and disk/container files | zip,7z,rar,tar,gz,tgz,bz2,xz,z,br,iso,ova,ovf,vhd,vhdx,vmdk |
| Web and markup | html,htm,xhtml,css,js,ts,jsx,tsx,wasm,xml,json,yaml,yml,ttl,rdf,n3,nq,trig,nt |
| Databases, logs and machine-readable exports | sql,sqlite,sqlite3,db,db3,log,ndjson,txt,bin,dat |
| Preservation packages and fixity sidecars | bagit,bag,md5,sha1,sha256,sha512,xml,mets,premis,sip,aip,dip,war,jar |

The format list is an operational catalog, not a promise that every product previews, OCRs, indexes, or preserves every extension. Intake and storage are separate from transformation and browser preview.

## Product-specific notes

- Version 4 changes the Java/Tomcat baseline; pin the server version to the selected Kitodo release.
