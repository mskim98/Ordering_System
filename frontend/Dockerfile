# frontend/Dockerfile
# 1. Node.js 20 사용
FROM node:20-alpine

# 2. 작업 디렉토리 설정
WORKDIR /app

# 3. 패키지 설치 및 의존성 복사
COPY package.json package-lock.json ./
RUN npm install

# 4. 소스코드 복사
COPY . .

# 5. 빌드 실행
RUN npm run build

# 6. 포트 노출
EXPOSE 3000

# 7. 개발 모드로 애플리케이션 실행
CMD ["npm", "run", "dev"]