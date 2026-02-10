# Meteor-PKI

RFC 4210/6712 표준을 준수하는 X.509 PKI CA(Certificate Authority) 서버입니다.
Rich Domain Model 기반의 레이어드 아키텍처로 설계되었으며, CMP(Certificate Management Protocol) API와 REST 관리 API를 함께 제공합니다.

---

## Architecture

### Module Structure

```
spring-boot-java-template (Meteor-PKI)
├── core/
│   ├── core-enum        # 도메인 공유 Enum (PKI 관련 9종 포함)
│   └── core-api         # 실행 모듈 — 도메인 모델, 서비스, API 컨트롤러
├── storage/
│   └── db-core          # JPA Entity, Spring Data Repository, BouncyCastle 의존성
├── support/
│   ├── logging          # Logback + Sentry 설정
│   └── monitoring       # Spring Actuator + Prometheus
├── clients/
│   └── client-example   # OpenFeign HTTP 클라이언트 예시
└── tests/
    └── api-docs         # Spring REST Docs 테스트 지원
```

### Dependency Flow

```
core/core-api  ──▶  storage/db-core  ──▶  core/core-enum
```

- `core/core-api`가 유일한 실행 모듈(bootJar)
- `storage/db-core`는 JPA 인프라와 BouncyCastle을 `core/core-api`로 전파
- 순환 의존성 방지: Repository Adapter는 `core/core-api` 내부에 위치

### PKI Domain Layer (`core/core-api`)

```
core/core-api
└── domain/pki/
    ├── vo/                         # Value Objects (불변, 자기검증)
    ├── ca/
    │   ├── CertificateAuthority    # Aggregate Root
    │   ├── CaAlias                 # VO
    │   ├── CaRepository            # 도메인 Repository 인터페이스
    │   ├── adapter/                # JPA 구현체 (CaRepositoryAdapter)
    │   └── service/                # CaManagementService, Commands
    ├── certificate/
    │   ├── IssuedCertificate       # Aggregate Root
    │   ├── IssuedCertificateRepository
    │   ├── adapter/
    │   └── service/                # CertificateIssuanceService
    ├── cmp/
    │   ├── CmpTransaction          # Entity
    │   ├── CmpTransactionRepository
    │   ├── adapter/
    │   └── service/                # CmpRequestProcessor, CmpMessageBuilder, CmpProtectionVerifier
    └── crypto/
        ├── CaKeyService            # 키 생성 + AES-256-GCM 암복호화
        ├── CertificateBuilderService   # X.509 인증서 빌드
        └── CrlBuilderService       # CRL 생성
```

### Storage Layer (`storage/db-core`)

```
storage/db-core
└── pki/
    ├── CaJpaEntity
    ├── IssuedCertificateJpaEntity
    ├── CmpTransactionJpaEntity
    ├── CaJpaRepository
    ├── IssuedCertificateJpaRepository
    └── CmpTransactionJpaRepository
```

---

## Domain Model

### Enums (`core/core-enum`)

| Enum | 값 |
|---|---|
| `CaType` | `ROOT` \| `INTERMEDIATE` \| `END_ENTITY_ISSUER` |
| `CaStatus` | `ACTIVE` \| `REVOKED` \| `EXPIRED` |
| `CertificateStatus` | `VALID` \| `REVOKED` \| `EXPIRED` \| `PENDING` |
| `KeyAlgorithmType` | `RSA_2048` \| `RSA_4096` \| `EC_P256` \| `EC_P384` |
| `RevocationReason` | `UNSPECIFIED(0)` \| `KEY_COMPROMISE(1)` \| `CA_COMPROMISE(2)` \| `AFFILIATION_CHANGED(3)` \| `SUPERSEDED(4)` \| `CESSATION_OF_OPERATION(5)` \| `CERTIFICATE_HOLD(6)` \| `PRIVILEGE_WITHDRAWN(9)` |
| `KeyUsageFlag` | `DIGITAL_SIGNATURE` \| `KEY_CERT_SIGN` \| `CRL_SIGN` \| `KEY_ENCIPHERMENT` \| `DATA_ENCIPHERMENT` \| `KEY_AGREEMENT` |
| `ExtendedKeyUsage` | `SERVER_AUTH` \| `CLIENT_AUTH` \| `CODE_SIGNING` \| `EMAIL_PROTECTION` |
| `CmpBodyType` | `IR` \| `IP` \| `CR` \| `CP` \| `P10CR` \| `RR` \| `RP` \| `CERT_CONF` \| `PKI_CONF` \| `ERROR` |
| `CmpTransactionStatus` | `PENDING` \| `WAITING_CONFIRM` \| `COMPLETED` \| `FAILED` |

### Value Objects (`domain/pki/vo/`)

| VO | 역할 |
|---|---|
| `CaId`, `IssuedCertificateId` | 식별자 래퍼 |
| `CmpTransactionId` | 16바이트 CMP 트랜잭션 ID, hex 변환 |
| `SubjectDN` | X.500 DN (CN/O/OU/C/ST/L), `toX500Name()` / `toRfc2253()` |
| `SerialNumber` | 128-bit crypto random 시리얼 |
| `KeyAlgorithm` | JCA 알고리즘명 · 서명 알고리즘 변환 |
| `CertificateValidity` | notBefore/notAfter, `isValid()` / `isExpired()` |
| `EncryptedPrivateKey` | 불투명 암호화 키 바이트 (Base64 직렬화) |
| `CertificatePem` | PEM ↔ DER ↔ X509Certificate 변환 |
| `CrlDistributionPoint` | CRL URL, 형식 검증 |
| `Nonce` | 16바이트 CMP Nonce |
| `SanValue` (sealed) | `DnsName` \| `IpAddress` \| `EmailAddress` |
| `SanExtension` | SAN 목록 |
| `KeyUsageExtension` | BouncyCastle bit 변환 |
| `ExtKeyUsageExtension` | `KeyPurposeId` OID 변환 |
| `CaChainDepth` | pathLen (-1 = unlimited) |

---

## Features

### Key Management
- RSA-2048/4096, ECDSA P-256/P-384 키쌍 생성
- PBKDF2(HMAC-SHA256) + AES-256-GCM으로 개인키 암호화 후 DB 저장

### Certificate Issuance
- **Root CA**: Self-signed, BasicConstraints(CA:true, unlimited), KeyUsage(keyCertSign + cRLSign)
- **Sub CA**: 부모 CA 서명, BasicConstraints(pathLen), AIA, AKI/SKI, CDP
- **End-Entity**: KeyUsage, ExtKeyUsage, SAN, AIA, AKI/SKI, CDP

### CRL
- X509v2 CRL, nextUpdate = 발급 시각 + 1일
- `GET /api/v1/pki/ca/{id}/crl` 로 즉시 생성·반환

### CMP Protocol (RFC 4210/6712)
- `ir` (Initialization Request) → `ip` 응답
- `cr` (Certification Request) → `cp` 응답
- `p10cr` (PKCS#10) → `cp` 응답
- `rr` (Revocation Request) → `rp` 응답
- `certConf` → `PKIConf` 응답
- MAC(PBMAC1) + 서명 기반 보호 모두 지원 구조

---

## API

### CMP Endpoint (RFC 6712)

```
POST /pki/{caAlias}
Content-Type: application/pkixcmp
Body: DER-encoded PKIMessage
→ DER-encoded PKIMessage 반환
```

### CA Management REST API

| Method | Path | 설명 |
|---|---|---|
| `POST` | `/api/v1/pki/ca/root` | Root CA 생성 |
| `POST` | `/api/v1/pki/ca` | Sub CA 생성 |
| `GET` | `/api/v1/pki/ca` | CA 목록 조회 |
| `GET` | `/api/v1/pki/ca/{id}` | CA 상세 조회 |
| `GET` | `/api/v1/pki/ca/{id}/certificate` | CA 인증서 (PEM) |
| `GET` | `/api/v1/pki/ca/{id}/chain` | CA 체인 PEM 목록 (root → target) |
| `GET` | `/api/v1/pki/ca/{id}/crl` | CRL (application/pkix-crl) |

#### Root CA 생성 예시

```json
POST /api/v1/pki/ca/root
{
  "alias": "root-ca",
  "cn": "Meteor Root CA",
  "o": "Meteor",
  "c": "KR",
  "keyAlgorithmType": "RSA_4096"
}
```

#### Sub CA 생성 예시

```json
POST /api/v1/pki/ca
{
  "alias": "issuing-ca",
  "cn": "Meteor Issuing CA",
  "o": "Meteor",
  "c": "KR",
  "keyAlgorithmType": "EC_P256",
  "parentId": 1
}
```

---

## Configuration

`application.yml`

```yaml
pki:
  key-encryption-secret: ${PKI_KEY_SECRET:dev-secret-change-in-prod}
  default-validity-days:
    root-ca: 7300    # 20년
    sub-ca: 3650     # 10년
    end-entity: 365  # 1년
  crl-distribution-base-url: ${PKI_CRL_BASE_URL:http://localhost:8080}
```

> `PKI_KEY_SECRET` 환경변수를 반드시 운영 환경에서 변경하세요.

---

## Tech Stack

| 항목 | 버전/선택 |
|---|---|
| Java | 25 (temurin-24 호환 확인) |
| Spring Boot | 4.0.0 |
| Spring Data JPA | Spring Boot BOM |
| BouncyCastle | 1.80 (`bcpkix-jdk18on`, `bcprov-jdk18on`) |
| Database | MySQL (운영) / H2 (local) |
| Build | Gradle 9 (multi-module) |

---

## Getting Started

### 1. 의존성 설치

```bash
./gradlew :core:core-api:build
```

### 2. 로컬 실행

```bash
./gradlew :core:core-api:bootRun --args='--spring.profiles.active=local'
```

### 3. Root CA 생성 후 인증서 체인 확인

```bash
# Root CA 생성
curl -X POST http://localhost:8080/api/v1/pki/ca/root \
  -H "Content-Type: application/json" \
  -d '{"alias":"root-ca","cn":"My Root CA","o":"MyOrg","c":"KR","keyAlgorithmType":"RSA_4096"}'

# Sub CA 생성 (parentId = 위 응답의 id)
curl -X POST http://localhost:8080/api/v1/pki/ca \
  -H "Content-Type: application/json" \
  -d '{"alias":"issuing-ca","cn":"My Issuing CA","o":"MyOrg","c":"KR","keyAlgorithmType":"EC_P256","parentId":1}'

# 체인 확인
curl http://localhost:8080/api/v1/pki/ca/2/chain
```

---

## Runtime Profiles

| Profile | 용도 |
|---|---|
| `local` | 네트워크 없이 개발 (H2 인메모리) |
| `local-dev` | 로컬에서 DEV 환경 DB 연결 |
| `dev` | 개발 서버 배포 |
| `staging` | 스테이징 서버 배포 |
| `live` | 운영 서버 배포 |

---

## Test Tasks

| Task | 설명 |
|---|---|
| `unitTest` | 단위 테스트 (빠름, 외부 의존 없음) |
| `contextTest` | Spring Context 로드 통합 테스트 |
| `restDocsTest` | Spring REST Docs 문서 생성 |
| `developTest` | CI 제외, 개발 중 사용 |

```bash
./gradlew unitTest
./gradlew contextTest
```

---

## Development Setup

### Git Hook (lint on commit)

```bash
git config core.hookspath .githooks
```

### IntelliJ IDEA

```
Build, Execution, Deployment > Build Tools > Gradle > Run tests using > IntelliJ IDEA
```
