# File-format catalog

ArchiveWeaver treats file acceptance, preservation, indexing, OCR, derivative generation, and browser preview as different capabilities. The extension inventory below is intentionally broad for planning and validation. A product adapter must declare the actual capabilities of the pinned release.

| Family | Extensions | Representative MIME types |
| --- | --- | --- |
| Documents | pdf,doc,docx,odt,ott,rtf,txt,md,tex,wpd,pages,xps,oxps | application/pdf,application/msword,application/vnd.openxmlformats-officedocument.wordprocessingml.document,text/plain,text/markdown |
| Spreadsheets and tabular data | xls,xlsx,ods,ots,csv,tsv,xml,json,parquet,feather,sav,dta | text/csv,application/vnd.ms-excel,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet,application/json |
| Presentations | ppt,pptx,odp,otp,key | application/vnd.ms-powerpoint,application/vnd.openxmlformats-officedocument.presentationml.presentation |
| Images and raster graphics | jpg,jpeg,jpe,png,gif,bmp,tif,tiff,jp2,j2k,jpf,jpx,jpm,mj2,webp,avif,heic,heif,svg,eps,psd,ico,raw,dng,cr2,cr3,nef,nrw,arw,orf,rw2,raf,pef,sr2,3fr,iiq | image/jpeg,image/png,image/tiff,image/jp2,image/svg+xml,image/webp,image/heic |
| Audio | wav,mp3,flac,ogg,oga,opus,m4a,aac,wma,aiff,aif,alac,ape,amr,midi,mid | audio/wav,audio/mpeg,audio/flac,audio/ogg,audio/mp4,audio/aac |
| Video | mp4,m4v,mov,avi,mkv,webm,ogv,mpg,mpeg,mpe,wmv,flv,asf,3gp,3g2,mxf,mts,m2ts,ts,vob | video/mp4,video/quicktime,video/x-msvideo,video/x-matroska,video/webm |
| E-books and page-description formats | epub,epub3,mobi,azw,azw3,fb2,djvu,cbr,cbz | application/epub+zip,application/x-mobipocket-ebook,image/vnd.djvu |
| Archives and disk/container files | zip,7z,rar,tar,gz,tgz,bz2,xz,z,br,iso,ova,ovf,vhd,vhdx,vmdk | application/zip,application/x-7z-compressed,application/gzip,application/x-tar |
| E-mail and messaging exports | eml,msg,mbox,pst,ost,emlx,ics,vcf | message/rfc822,application/vnd.ms-outlook,application/mbox,text/calendar,text/vcard |
| Web and markup | html,htm,xhtml,css,js,ts,jsx,tsx,wasm,xml,json,yaml,yml,ttl,rdf,n3,nq,trig,nt | text/html,application/xhtml+xml,application/xml,application/json,text/turtle |
| Scientific, research and geospatial data | hdf,hdf5,netcdf,nc,mat,fits,fits.gz,fastq,fasta,fa,geojson,gpkg,kml,kmz,shp,shx,dbf,prj,las,laz,dcm,dicom | application/x-hdf,application/netcdf,application/geo+json,application/dicom |
| Databases, logs and machine-readable exports | sql,sqlite,sqlite3,db,db3,log,ndjson,txt,bin,dat | application/sql,application/x-sqlite3,text/plain,application/octet-stream |
| Fonts | ttf,otf,woff,woff2 | font/ttf,font/otf,font/woff,font/woff2 |
| Preservation packages and fixity sidecars | bagit,bag,md5,sha1,sha256,sha512,xml,mets,premis,sip,aip,dip,war,jar | application/xml,application/war,application/java-archive,application/octet-stream |

## Operational policy

- Do not reject a file solely from its extension; verify magic bytes and MIME detection where the application supports it.
- Keep the original bitstream immutable and record SHA-256 (or stronger) fixity.
- Store a preservation event for normalization, OCR, virus scanning, preview generation, and failed transformations.
- Product-specific preview/OCR support may require ImageMagick, FFmpeg, LibreOffice, Apache Tika, ExifTool, Ghostscript, Tesseract, MediaInfo, or a dedicated format registry.
- Add new extensions through a pull request with an upstream reference and a test fixture.
