# Docspell

ArchiveWeaver adapter facts for planning, checking and repair. Product behavior remains governed by the upstream release documentation.

- **Category:** document-management
- **License:** GPL-3.0
- **Upstream repository:** https://github.com/eikek/docspell
- **Canonical source repository:** https://github.com/eikek/docspell
- **Official documentation:** https://docspell.org/docs/
- **Homepage:** https://docspell.org/
- **Default HTTP port:** 7880
- **Container image hint:** `No image pinned; use the upstream release or approved internal registry.`

## Architecture components

- Docspell restserver
- Joex workers
- PostgreSQL
- Solr
- Tika
- OCR tools
- file storage

## Dependencies

- JVM
- PostgreSQL
- Solr
- Tika
- Tesseract
- OCRmyPDF
- S3/filesystem

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

`native` and `validated` refer to an upstream or repository-backed path. `portable` means ArchiveWeaver can render and check the runtime pattern, but the product's own HA guarantees and state model must be validated. `conditional` requires an explicit design review. `not-recommended` is intentionally blocked by the planner unless an exception is documented.

## Health checks

- `process-or-service`
- `http`
- `storage-paths`
- `dependency-reachability`
- `configuration-presence`

Service aliases: `docspell, solr, postgresql`

HTTP paths: `/`

## Format families

| Family | Extensions in the ArchiveWeaver catalog |
| --- | --- |
| Documents | pdf,doc,docx,odt,ott,rtf,txt,md,tex,wpd,pages,xps,oxps |
| Images and raster graphics | jpg,jpeg,jpe,png,gif,bmp,tif,tiff,jp2,j2k,jpf,jpx,jpm,mj2,webp,avif,heic,heif,svg,eps,psd,ico,raw,dng,cr2,cr3,nef,nrw,arw,orf,rw2,raf,pef,sr2,3fr,iiq |
| E-mail and messaging exports | eml,msg,mbox,pst,ost,emlx,ics,vcf |
| Archives and disk/container files | zip,7z,rar,tar,gz,tgz,bz2,xz,z,br,iso,ova,ovf,vhd,vhdx,vmdk |
| Databases, logs and machine-readable exports | sql,sqlite,sqlite3,db,db3,log,ndjson,txt,bin,dat |

The format list is an operational catalog, not a promise that every product previews, OCRs, indexes, or preserves every extension. Intake and storage are separate from transformation and browser preview.

## Product-specific notes

- The project provides Docker Compose and Helm paths; the Debian package and Helm chart are better baselines than ad-hoc source builds.
