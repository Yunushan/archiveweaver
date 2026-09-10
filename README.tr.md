# ArchiveWeaver

Dijital arşivleme platformları için kurulum planlama, kurulum zarfı üretme, sağlık kontrolü ve kontrollü onarım otomasyonu.

ArchiveWeaver; araştırma veri depoları, dijital koruma sistemleri, DMS/ECM ürünleri, DAM çözümleri, arşiv tanımlama araçları ve dosya senkronizasyon sistemleri için ortak bir operasyon modeli sağlar.

## Önerilen GitHub kimliği

- **Proje adı:** ArchiveWeaver
- **Repository adı:** `archiveweaver`
- **Önerilen URL:** `https://github.com/Yunushan/archiveweaver`
- **Kısa açıklama:** `Production deployment, health-check, and safe-repair automation for open digital archiving platforms.`
- **Lisans:** 0BSD

`archiveweaver`; mevcut otomasyon projelerinizdeki Weaver isimlendirmesiyle uyumlu, CLI ve paket isimlerinde kullanılabilecek kadar kısa ve kolay hatırlanabilen bir addır.

## Kapsam

- 30 çözüm için upstream repository, resmi dokümantasyon, bağımlılık, servis, sağlık yolu ve format ailesi kataloğu;
- raw/native, Docker Compose, K3s, RKE2, Pacemaker/Corosync + STONITH, Podman Quadlet, k0s, Docker Swarm ve MicroK8s;
- inventory, Vault/secret sınırı, fail-closed approval, rolling execution, provider envelope, repair gate ve evidence içeren Ansible orchestration edition;
- standalone, 2 node, 3 node ve 3+ node topolojileri;
- Ubuntu 22.04/24.04/26.04, Rocky Linux 8/9/10, RHEL 8/9/10, AlmaLinux 8/9/10, Debian 12/13;
- salt-okunur host, runtime, systemd, HTTP, storage path ve configuration kontrolleri;
- plan-only ve açıkça izin verilmiş onarım işlemleri;
- systemd, Docker, Quadlet, Swarm ve Kubernetes ailesi için güvenli deployment envelope çıktıları;
- HLD, LLD, ADR, deployment, backup/restore, security ve format dokümanları;
- İngilizce varsayılan README ve Türkçe README/operasyon özetleri;
- stdlib testleri ve GitHub Actions CI.

## Destek seviyeleri

- **native:** upstream projesinde bu moda uygun kaynak/paket/kurulum yolu var;
- **validated:** upstream proje bu deployment yolunu dokümante ediyor veya yayınlıyor;
- **portable:** ArchiveWeaver altyapı desenini üretebilir/kontrol edebilir; uygulamanın HA ve state davranışı ayrıca doğrulanmalıdır;
- **conditional:** tasarım incelemesi, release pinleme ve failure testinden sonra kullanılabilir;
- **not-recommended:** belgelenmiş istisna yoksa planner tarafından bloklanır.

Bir container'ın başlatılabilmesi, ürünün vendor destekli HA olduğu anlamına gelmez. Hyrax bir Rails engine'dir; Islandora Drupal/Fedora/Solr bileşimidir; Archivematica ve Alfresco çoklu servis yapısındadır; Fedora Repository backend'dir. OpenKM'in resmi GitHub repository'si 2026'da arşivlenmiştir. Bu bilgiler katalogda görünür durumdadır.

## Hızlı başlangıç

```bash
git clone https://github.com/Yunushan/archiveweaver.git
cd archiveweaver

python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .

archiveweaver validate-catalog --json
archiveweaver list-solutions
```

Üç node RKE2 planı:

```bash
archiveweaver plan \
  --solution paperless-ngx \
  --mode rke2 \
  --nodes 3 \
  --os ubuntu-24.04
```

Salt-okunur kontrol:

```bash
archiveweaver check \
  --solution paperless-ngx \
  --mode rke2 \
  --url https://paperless.example.org/ \
  --service paperless \
  --path /srv/paperless \
  --config /etc/rancher/rke2/config.yaml \
  --json > reports/paperless-check.json
```

Enterprise Ansible orchestration edition:

```bash
cd deploy/ansible
cp inventory/production/hosts.yml.example inventory/production/hosts.yml
bash ../../scripts/run-ansible-operational.sh site.yml --syntax-check -i inventory/production/hosts.yml
bash ../../scripts/run-ansible-operational.sh site.yml --check --diff -i inventory/production/hosts.yml -e archiveweaver_apply=true
```

Belirli bir provider için inceleme amaçlı Ansible entry point üretmek üzere örneğin
`archiveweaver render --solution paperless-ngx --mode ansible --underlying-mode rke2 --nodes 3 --os ubuntu-24.04 --output deploy/ansible/generated/paperless-rke2.yml` kullanılabilir.
Üretim işlemleri sabit onaylı playbook'ları
`scripts/run-ansible-operational.sh` üzerinden kullanır.
Controller execution environment imajını yalnızca
`scripts/build-ansible-execution-environment.sh` ile oluşturun; Podman veya
Docker çalıştırılmadan önce değişmez base-image digest'i zorunlu kılar.

Operasyon runner'ı tam olarak bir production, staging veya restore envanteri
ister; yalnızca açık `archiveweaver_*` anahtar/değer bağlarını kabul eder.
Envanter dizinleri, extra-vars dosyaları, ham YAML/JSON değişkenleri ve
controller/transport override'ları reddedilir.

Ansible seçilen provider'ı koordine eder; quorum, fencing, scheduler HA,
database replication veya ürün seviyesinde failover sağlamaz. Release
manifest, dependency stack, backup kanıtı ve change approval tamamlanana
kadar `archiveweaver_apply: false` bırakılmalıdır.

Üretim değişikliğinden önce 100 puanlık readiness gate çalıştırın:
`PYTHONPATH=src python3 -m archiveweaver readiness --manifest deploy/ansible/release-manifest.json --json`.
Örnek, gerçek release manifesti, ürün test kanıtları ve doğrulanmış SHA-256
evidence index sağlanana kadar bilerek başarısız olur. Sözleşme için [premium
readiness](docs/operations/premium-readiness.md) sayfasına bakın.

Onarım varsayılan olarak yalnızca plan üretir. Uygulamak için açıkça `--apply` gerekir:

```bash
archiveweaver repair \
  --solution paperless-ngx \
  --mode docker \
  --compose-file /srv/paperless/docker-compose.yml \
  --json > reports/paperless-repair-plan.json
```

## Çözüm grupları

| Grup | Ürünler |
| --- | --- |
| Araştırma depoları | InvenioRDM, DSpace, Dataverse, EPrints |
| Dijital koruma | Archivematica, RODA Community, Asalae, Maarch RM |
| Repository backend/framework | Fedora Repository, Samvera Hyrax, Islandora |
| DMS/ECM | Mayan EDMS, Maarch Courrier, Docspell, Alfresco Community, SeedDMS, Paperless-ngx, Papermerge, OpenKM Community, Teedy, LogicalDOC Community |
| DAM/collections/tanımlama | ResourceSpace, ArchivesSpace, AtoM, CollectiveAccess, Omeka S |
| Dosya senkronizasyonu | Nextcloud Server, Seafile Community |
| Dijitalleştirme workflow | Kitodo.Production, Goobi workflow |

Detaylı katalog: [solutions-catalog.md](docs/reference/solutions-catalog.md). Ürün bazlı sayfalar: [`docs/solutions/`](docs/solutions/). Toplu görünüm için [product support matrix](docs/reference/support-matrix.md) ve [format-family matrix](docs/reference/format-matrix.md) dosyaları vardır.

## Runtime ve topoloji

| Runtime | Standalone | 2 node | 3 node | 3+ node |
| --- | --- | --- | --- | --- |
| Raw/native | destekli | koşullu | koşullu | koşullu |
| Docker Compose | destekli | koşullu | koşullu | koşullu |
| K3s | destekli | önerilmez | destekli | destekli |
| RKE2 | destekli | önerilmez | destekli | destekli |
| Pacemaker/Corosync + STONITH | destekli | STONITH ile | destekli | destekli |
| Podman Quadlet | destekli | koşullu | koşullu | koşullu |
| k0s | destekli | önerilmez | destekli | destekli |
| Docker Swarm | destekli | önerilmez | destekli | destekli |
| MicroK8s | destekli | önerilmez | destekli | destekli |
| Ansible orchestration adapter | destekli | destekli | destekli | destekli |

İki node embedded-etcd veya iki Swarm manager yapısı, tek node kaybında quorum koruyan HA olarak kabul edilmez. İki node Pacemaker tasarımında gerçek STONITH/fencing zorunludur. Ayrıntı için [runtime matrix](docs/deployment/runtime-matrix.md) ve [two-node design](docs/deployment/two-node.md) sayfalarına bakın.

Ansible satırı, koordine edilebilen host sayısını gösterir; tek başına HA
garantisi değildir. Dayanıklılığı underlying runtime ve uygulamanın state
tasarımı belirler.

## Linux tabanı

ArchiveWeaver şu işletim sistemlerini kataloglar ve kontrol eder:

- Ubuntu 22.04 LTS;
- Ubuntu 24.04 LTS (yeni kurulumlar için tercih edilen);
- Ubuntu 26.04 LTS (forward validation);
- Rocky Linux 8/9/10;
- RHEL 8/9/10;
- AlmaLinux 8/9/10;
- Debian 12/13.

Bu liste ArchiveWeaver host baseline'ıdır; tüm ürünlerin tüm release'leri için otomatik vendor sertifikasyonu anlamına gelmez. [OS matrix](docs/deployment/os-matrix.md) dosyasını inceleyin.

## Mimari dokümanlar

- [HLD](docs/architecture/HLD.md): logical architecture, HA desenleri, veri koruma, security ve failure domain'leri;
- [LLD](docs/architecture/LLD.md): katalog sözleşmesi, CLI, renderer, repair güvenliği, portlar ve evidence bundle;
- [ADR](docs/architecture/DECISIONS.md): katalog yaklaşımı, iki node quorum politikası ve envelope kararı;
- [Standalone](docs/deployment/standalone.md), [two-node](docs/deployment/two-node.md), [three-node](docs/deployment/three-node.md), [three-plus-node](docs/deployment/three-plus-node.md);
- [Kubernetes ailesi](docs/deployment/kubernetes.md), [containers](docs/deployment/containers.md), [Pacemaker](docs/deployment/pacemaker.md);
- [Ansible enterprise orchestration](docs/deployment/ansible.md) ve çalıştırılabilir [Ansible edition](deploy/ansible/README.md);
- [Checking](docs/operations/checking.md), [repair](docs/operations/repair.md), [backup/restore](docs/operations/backup-restore.md), [product certification](docs/operations/product-certification.md), [service management](docs/operations/service-management.md) ve [security](docs/operations/security.md);
- [Supply-chain controls](docs/operations/supply-chain.md);
- [format kataloğu](docs/reference/formats.md), [format-family matrix](docs/reference/format-matrix.md), [product support matrix](docs/reference/support-matrix.md) ve [upstream kaynakları](docs/reference/upstream-sources.md).

## Format modeli

Format kataloğu documents, spreadsheets, presentations, images, audio, video, e-books, archives, e-mail exports, web/markup, scientific/geospatial, structured data, fonts ve preservation paketlerini içerir.

Extension listesinin bulunması, ürünün bu dosyayı preview, OCR, index veya preservation normalization yapabildiği anlamına gelmez. Şu yetenekler ayrı test edilir:

1. intake/upload;
2. bitstream saklama;
3. MIME/magic-byte tanımlama;
4. virus scanning;
5. OCR/text extraction;
6. preview/derivative üretimi;
7. indexing/search;
8. preservation normalization/fixity.

## Güvenlik modeli

- plan ve check salt-okunurdur;
- repair yalnızca `--apply` ile çalışır;
- Pacemaker repair ayrıca `--allow-fencing-actions` ister;
- `down -v`, PVC silme, data purge, TLS doğrulamasını kapatma, auth bypass veya STONITH disable işlemleri yerleşik olarak yoktur;
- image'lar digest veya immutable tag ile pinlenmelidir;
- secret, token, private key ve kişisel arşiv belgeleri repository'ye yazılmaz.

## Geliştirme

```bash
make generate
make validate
make test
make smoke
```

Yeni ürün veya bilgi eklemek için `src/archiveweaver/catalog_source.py` dosyasını değiştirin, upstream kaynaklarını ekleyin, catalog'u regenerate edin ve test/failure koşullarını belgelendirin.

## Lisans

ArchiveWeaver [0BSD](LICENSE) lisanslıdır. Referans verilen upstream ürünlerin kendi lisansları; image, plugin ve deployment bağımlılıkları için ayrıca geçerlidir.
