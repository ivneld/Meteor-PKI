# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

---

## Commands

### Build & Compile

```bash
# 전체 빌드 (javaVersion=25 필요, 없으면 gradle.properties에서 24로 임시 변경)
./gradlew :core:core-api:build

# 컴파일만
./gradlew :core:core-api:compileJava

# 특정 모듈 빌드
./gradlew :storage:db-core:build
./gradlew :core:core-enum:build
```

### Test

```bash
# CI용 기본 테스트 (develop, restdocs 태그 제외)
./gradlew test

# 단위 테스트만 (context, restdocs, develop 태그 제외)
./gradlew unitTest

# Spring Context 통합 테스트
./gradlew contextTest

# Spring REST Docs 생성
./gradlew restDocsTest

# 특정 테스트 클래스 실행
./gradlew :core:core-api:test --tests "io.dodn.springboot.core.domain.pki.ca.CertificateAuthorityTest"
```

테스트 태그 규칙:
- `@Tag("context")` — Spring Context 로드 필요
- `@Tag("restdocs")` — REST Docs 생성
- `@Tag("develop")` — CI 제외, 로컬 개발 전용

### Lint & Format

```bash
# 포맷 검사 (pre-commit hook이 자동 실행)
./gradlew checkFormat

# 포맷 자동 수정
./gradlew format
```

> `git config core.hookspath .githooks` 설정 시 커밋마다 `checkFormat` 자동 실행.

### Run

```bash
./gradlew :core:core-api:bootRun --args='--spring.profiles.active=local'
```

---

## Architecture

### Module Dependency

```
core/core-api (bootJar)
  └── storage/db-core  ──▶  core/core-enum
  └── support/logging
  └── support/monitoring
  └── clients/client-example
```

- **`core/core-api`** 가 유일한 실행 모듈. 도메인 모델·서비스·컨트롤러·Repository Adapter 전부 여기에 위치.
- **`storage/db-core`** 는 JPA Entity + Spring Data Repository + BouncyCastle을 `api` 스코프로 노출. `core/core-api`는 이를 통해 BouncyCastle을 사용.
- **`core/core-api` → `storage/db-core`** 단방향이므로 `storage/db-core` 내부에 `core/core-api` 도메인 클래스를 import하면 순환 의존성 발생. **Repository Adapter는 반드시 `core/core-api` 안에 위치해야 한다.**

### PKI 도메인 레이어 구조 (`core/core-api`)

```
domain/pki/
├── vo/                          # 모든 Value Object (record 기반, 불변)
├── ca/
│   ├── CertificateAuthority     # Aggregate Root
│   ├── CaAlias                  # VO (alias 유효성 검증: 소문자+숫자+하이픈)
│   ├── CaRepository             # 도메인 인터페이스
│   ├── adapter/CaRepositoryAdapter       # JPA 구현체
│   └── service/CaManagementService       # Root/Sub CA 생성, 체인 조회, CRL 발급
├── certificate/
│   ├── IssuedCertificate        # Aggregate Root
│   ├── IssuedCertificateRepository
│   ├── adapter/
│   └── service/CertificateIssuanceService  # 인증서 발급·폐지
├── cmp/
│   ├── CmpTransaction           # Entity
│   ├── CmpTransactionRepository
│   ├── adapter/
│   └── service/
│       ├── CmpRequestProcessor  # ir/cr/p10cr/rr/certConf 라우팅
│       ├── CmpProtectionVerifier
│       └── CmpMessageBuilder    # ip/cp/rp/PKIConf/error 응답 빌드
└── crypto/
    ├── CaKeyService             # 키 생성 (RSA/EC), AES-256-GCM 암복호화
    ├── CertificateBuilderService  # X.509 Root CA / Sub CA / End-Entity 빌드
    └── CrlBuilderService        # X509v2 CRL 빌드
```

### Storage 레이어 (`storage/db-core`)

JPA Entity와 Spring Data Repository만 존재. 도메인 클래스를 참조하지 않는다.

```
storage/db/core/pki/
├── CaJpaEntity / CaJpaRepository
├── IssuedCertificateJpaEntity / IssuedCertificateJpaRepository
└── CmpTransactionJpaEntity / CmpTransactionJpaRepository
```

### API 레이어 (`core/core-api`)

```
api/controller/
├── CmpController               POST /pki/{caAlias}  (application/pkixcmp)
├── CaManagementController      /api/v1/pki/ca/**
└── ApiControllerAdvice         CoreException → ApiResponse<ErrorMessage>
api/config/
├── BouncyCastleConfig          Security.addProvider(new BouncyCastleProvider()) — static 블록
└── PkiProperties               @ConfigurationProperties(prefix = "pki")
```

모든 REST 응답은 `ApiResponse<T>` 로 래핑: `{ result: "SUCCESS"|"ERROR", data: ..., error: ... }`.

예외는 `CoreException(ErrorType)` 으로 던지고 `ApiControllerAdvice` 가 HTTP 상태 코드와 함께 변환.

---

## Key Conventions

### 새 도메인 추가 시 체크리스트

1. Enum → `core/core-enum/.../enums/`
2. VO → `core/core-api/.../domain/<도메인>/vo/`
3. Domain Entity + Repository 인터페이스 → `core/core-api/.../domain/<도메인>/`
4. JPA Entity + Spring Data Repository → `storage/db-core/.../storage/db/core/<도메인>/`
5. Repository Adapter (`implements` 도메인 인터페이스) → `core/core-api/.../domain/<도메인>/adapter/`
6. Service → `core/core-api/.../domain/<도메인>/service/`
7. Controller + DTO → `core/core-api/.../api/controller/`
8. ErrorType/ErrorCode 추가 → `core/core-api/.../support/error/`

### BouncyCastle 1.80 주요 주의사항

- `CertReqMessages`, `CertReqMsg` → `org.bouncycastle.asn1.crmf` (cmp 아님)
- `CertResponse` 첫 번째 인자 → `ASN1Integer` (BigInteger 아님)
- `JcaX509v2CRLBuilder` 첫 번째 인자 → `X509Certificate` (X500Name 아님)
- `RevRepContent` 직접 생성 → `RevRepContent.getInstance(new DERSequence(vector))`

### JPA / DB

- `local` 프로파일은 H2 in-memory + `ddl-auto: create`
- 운영 프로파일은 `ddl-auto: validate` → **Entity 변경 시 반드시 마이그레이션 스크립트 필요**
- `BaseEntity` 상속: `id` (AUTO_INCREMENT), `createdAt`, `updatedAt` 자동 관리

### Java Toolchain

- `gradle.properties`의 `javaVersion=25` 설정. 로컬에 Java 25가 없으면 `24`로 임시 변경 후 컴파일 검증.
