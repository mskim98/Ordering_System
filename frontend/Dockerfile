# frontend/Dockerfile
# 1. Node.js 20 사용
FROM node:20-alpine

# 2. 작업 디렉토리 설정
WORKDIR /app

# 3. 패키지 설치 및 의존성 복사
COPY package.json package-lock.json ./

# 4. 의존성 설치
RUN npm install

# 5. 소스코드 복사
COPY . .

# 6. 빌드 실행
RUN npm run build

# 7. 포트 노출
EXPOSE 3000

# 8. 애플리케이션 실행
CMD ["npm", "run", "dev"]