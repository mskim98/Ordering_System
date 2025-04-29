FROM nginx:alpine

# 기본 nginx 설정 파일 제거
RUN rm /etc/nginx/conf.d/default.conf

# 커스텀 설정 파일 복사
COPY default.conf /etc/nginx/conf.d/

# 80 포트 노출
EXPOSE 80

# nginx 실행
CMD ["nginx", "-g", "daemon off;"] 