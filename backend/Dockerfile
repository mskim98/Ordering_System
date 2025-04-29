# backend/Dockerfile
# 1. Node.js 20 사용
FROM node:20-alpine AS builder

# bcrypt 및 기타 네이티브 모듈을 위한 빌드 도구 설치
RUN apk add --no-cache python3 make g++ git

# 2. 작업 디렉토리 설정
WORKDIR /app

# 3. pnpm 설치
RUN npm install -g pnpm

# 4. 의존성/패키지 설치 및 의존성 복사
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile

# 5. 추가 종속성 설치 - 빌드 오류 해결
RUN pnpm add bcryptjs @types/bcryptjs class-validator class-transformer
RUN pnpm rebuild bcrypt || true

# 6. 소스코드 복사
COPY . .

# 7. 빌드 실행
RUN pnpm build

# 8. 운영 이미지 생성
FROM node:20-alpine AS runner

WORKDIR /app

# bcrypt 실행에 필요한 라이브러리 설치
RUN apk add --no-cache libc6-compat

# pnpm 설치
RUN npm install -g pnpm

# 9. 빌드 결과물 및 필요한 파일만 복사
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./package.json

# 10. 포트 노출
EXPOSE 3001

# 11. 애플리케이션 실행 (개발 환경용)
CMD ["pnpm", "start:dev"]