# Samvera Hyrax

ArchiveWeaver adapter facts for planning, checking and repair. Product behavior remains governed by the upstream release documentation.

- **Category:** repository-application-framework
- **License:** Apache-2.0
- **Upstream repository:** https://github.com/samvera/hyrax
- **Canonical source repository:** https://github.com/samvera/hyrax
- **Official documentation:** https://samvera.org/get-started/getting-started
- **Homepage:** https://hyrax.samvera.org/
- **Default HTTP port:** 3000
- **Container image hint:** `No image pinned; use the upstream release or approved internal registry.`

## Architecture components

- Rails host application
- Hyrax engine
- Solr
- Fedora/ActiveFedora
- Redis
- PostgreSQL
- S3 storage

## Dependencies

- Ruby
- Rails
- Solr
- PostgreSQL
- Redis
- Fedora or ActiveFedora
- S3

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

Service aliases: `hyrax, puma, solr, redis`

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
| Scientific, research and geospatial data | hdf,hdf5,netcdf,nc,mat,fits,fits.gz,fastq,fasta,fa,geojson,gpkg,kml,kmz,shp,shx,dbf,prj,las,laz,dcm,dicom |
| Databases, logs and machine-readable exports | sql,sqlite,sqlite3,db,db3,log,ndjson,txt,bin,dat |
| Preservation packages and fixity sidecars | bagit,bag,md5,sha1,sha256,sha512,xml,mets,premis,sip,aip,dip,war,jar |

The format list is an operational catalog, not a promise that every product previews, OCRs, indexes, or preserves every extension. Intake and storage are separate from transformation and browser preview.

## Product-specific notes

- Hyrax is a Rails engine and must be mounted in a host application; it is not a standalone web app.
