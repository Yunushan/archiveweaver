# Alfresco Community Edition

ArchiveWeaver adapter facts for planning, checking and repair. Product behavior remains governed by the upstream release documentation.

- **Category:** enterprise-content-management
- **License:** LGPL-3.0
- **Upstream repository:** https://github.com/Alfresco/alfresco-community-repo
- **Canonical source repository:** https://github.com/Alfresco/alfresco-community-repo
- **Official documentation:** https://docs.hyland.com/r/Alfresco/Alfresco-Content-Services-Community-Edition/23.3/Alfresco-Content-Services-Community-Edition/Install/Overview
- **Homepage:** https://www.alfresco.com/
- **Default HTTP port:** 8080
- **Container image hint:** `alfresco/alfresco-content-repository-community`

## Architecture components

- Repository
- Share/UI
- Search/Solr
- PostgreSQL
- ActiveMQ
- Transform Service
- S3/filesystem storage

## Dependencies

- Java
- Tomcat
- PostgreSQL
- Solr
- ActiveMQ
- Transform services
- Docker/Compose

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

Service aliases: `alfresco, tomcat, solr, postgresql, activemq`

HTTP paths: `/`

## Format families

| Family | Extensions in the ArchiveWeaver catalog |
| --- | --- |
| Documents | pdf,doc,docx,odt,ott,rtf,txt,md,tex,wpd,pages,xps,oxps |
| Spreadsheets and tabular data | xls,xlsx,ods,ots,csv,tsv,xml,json,parquet,feather,sav,dta |
| Presentations | ppt,pptx,odp,otp,key |
| Images and raster graphics | jpg,jpeg,jpe,png,gif,bmp,tif,tiff,jp2,j2k,jpf,jpx,jpm,mj2,webp,avif,heic,heif,svg,eps,psd,ico,raw,dng,cr2,cr3,nef,nrw,arw,orf,rw2,raf,pef,sr2,3fr,iiq |
| Audio | wav,mp3,flac,ogg,oga,opus,m4a,aac,wma,aiff,aif,alac,ape,amr,midi,mid |
| Video | mp4,m4v,mov,avi,mkv,webm,ogv,mpg,mpeg,mpe,wmv,flv,asf,3gp,3g2,mxf,mts,m2ts,ts,vob |
| E-books and page-description formats | epub,epub3,mobi,azw,azw3,fb2,djvu,cbr,cbz |
| Archives and disk/container files | zip,7z,rar,tar,gz,tgz,bz2,xz,z,br,iso,ova,ovf,vhd,vhdx,vmdk |
| E-mail and messaging exports | eml,msg,mbox,pst,ost,emlx,ics,vcf |
| Web and markup | html,htm,xhtml,css,js,ts,jsx,tsx,wasm,xml,json,yaml,yml,ttl,rdf,n3,nq,trig,nt |
| Databases, logs and machine-readable exports | sql,sqlite,sqlite3,db,db3,log,ndjson,txt,bin,dat |

The format list is an operational catalog, not a promise that every product previews, OCRs, indexes, or preserves every extension. Intake and storage are separate from transformation and browser preview.

## Product-specific notes

- Alfresco Community is a multi-module platform; deploy the repository, search, Share, transforms, database, and messaging as a tested release set.
