import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import {
  LoggerService,
  LoggingInterceptor,
  HttpExceptionFilter,
} from './common/logger';
import { ConfigService } from '@nestjs/config';

async function bootstrap() {
  // 로거 서비스 생성 및 애플리케이션에 적용
  const app = await NestFactory.create(AppModule, {
    bufferLogs: true, // NestJS 기본 로거 버퍼링
  });

  // ConfigService 인스턴스 가져오기
  const configService = app.get(ConfigService);

  // 커스텀 로거 서비스 인스턴스 가져오기
  const loggerService = app.get(LoggerService);

  // 애플리케이션 로거 설정
  app.useLogger(loggerService);

  // 글로벌 인터셉터 및 필터 적용
  app.useGlobalInterceptors(new LoggingInterceptor(loggerService));
  app.useGlobalFilters(new HttpExceptionFilter(loggerService));

  // Validation 파이프
  app.useGlobalPipes(
    new ValidationPipe({
      transform: true,
      whitelist: true,
      forbidNonWhitelisted: true,
    }),
  );

  // Swagger 설정
  const config = new DocumentBuilder()
    .setTitle('판크로스 발주 시스템')
    .setDescription('판크로스 발주 시스템 API 문서')
    .setVersion('1.0')
    .addBearerAuth(
      {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        name: 'JWT',
        description: 'Enter JWT token',
        in: 'header',
      },
      'JWT-auth',
    )
    .addBasicAuth(
      {
        type: 'http',
        scheme: 'basic',
        name: 'Basic',
        description: 'Enter email and password',
        in: 'header',
      },
      'Basic-auth',
    )
    .build();

  const document = SwaggerModule.createDocument(app, config);

  SwaggerModule.setup('doc', app, document, {
    swaggerOptions: {
      persistAuthorization: true,
    },
  });

  // 애플리케이션 시작
  const port = configService.get<number>('PORT', 3000);
  await app.listen(port);

  loggerService.log(
    `애플리케이션이 ${port} 포트에서 시작되었습니다`,
    'Bootstrap',
  );
}

bootstrap().catch((err) => {
  console.error('애플리케이션 부팅 실패:', err);
  process.exit(1);
});
