# backend/Dockerfile
# 1. Node.js 20 사용
FROM node:20-alpine

# 2. 작업 디렉토리 설정
WORKDIR /app

# 3. pnpm 설치
RUN npm install -g pnpm

# 4. 의존성/패키지 설치 및 의존성 복사
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile

# 6. 소스코드 복사
COPY . .

# 7. 빌드 실행
RUN pnpm build

# 8. 포트 노출
EXPOSE 3001

# 9. 애플리케이션 실행
CMD ["pnpm", "start:dev"]