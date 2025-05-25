# 발주 자동화 시스템 (Ordering System)

## 프로젝트 개요

이 프로젝트는 기업의 발주 프로세스를 자동화하고 효율적으로 관리할 수 있는 시스템입니다. 발주 요청부터 승인, 배송 등의 전체 프로세스를 디지털화하여 관리합니다.

## 기술 스택

### 백엔드

- Node.js
- NestJS (TypeScript)
- PostgreSQL
- Nginx
- Docker

### 프론트엔드

- Next.js
- TypeScript
- Tailwind CSS

## 주요 기능

### 사용자 관리

- JWT 기반 인증 시스템
- 사용자 프로필 관리
- 권한 관리 (일반 사용자/관리자/파트너)
- 권한 기반 접근제어(RBAC)

### 발주 관리

- 발주 요청 생성 및 관리
- 발주 승인 프로세스
- 발주 이력 추적
- 자동 발주

## 시스템 아키텍처

![Screenshot 2025-01-27 at 3 17 04 PM](https://github.com/user-attachments/assets/0060d315-065b-49a9-a144-03ace2c8aee1)

### 백엔드 구조
```
backend/
├── src/
│   ├── auth/         # 인증 및 권한 관리
│   ├── common/       # 공통 모듈 (인터셉터, DTO 등)
│   ├── item/         # 품목 관리
│   ├── logistics/    # 물류 관리
│   ├── order/        # 발주 관리
│   ├── owner/        # 점주 관리
│   ├── store/        # 점포 관리
│   ├── types/        # 타입 정의
│   ├── user/         # 사용자 관리
│   ├── app.module.ts # 루트 모듈
│   └── main.ts       # 애플리케이션 진입점
```

### 프론트엔드 구조
```
frontend/
├── src/
│   ├── app/          # Next.js 앱 라우터
│   ├── components/   # 재사용 가능한 컴포넌트
│   ├── hooks/        # 커스텀 훅
│   └── styles/       # 스타일 관련 파일
```

## 설치 및 실행

### 개발 환경 설정

1. 저장소 클론

```bash
git clone [repository-url]
```

2. 백엔드 설정

```bash
cd backend
pnpm install
```

3. 프론트엔드 설정

```bash
cd frontend
pnpm install
```

### Docker를 이용한 실행

```bash
docker-compose up
```

## API 문서

API 문서는 Swagger를 통해 제공됩니다:

- 개발 환경: http://localhost:3000/api/docs
- 프로덕션 환경: [production-url]/api/docs

## 배포

- Docker 컨테이너를 통한 배포
- nginx를 통한 리버스 프록시 설정
- 환경 변수를 통한 설정 관리

## 보안

- JWT 토큰 기반 인증
- 입력 데이터 검증
- SQL 인젝션 방지
- XSS 방지
- 데이터 암호화

## 모니터링

- 로그 시스템 구현
