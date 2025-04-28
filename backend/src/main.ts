import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.useGlobalPipes(
    new ValidationPipe({
      /** 입력 데이터 외 무시 옵션 */
      whitelist: true,
      forbidNonWhitelisted: true,
      /** class-validator 사용 시 명시된 타입으로 자동 타입 변환 */
      transformOptions: {
        enableImplicitConversion: true,
      },
    }),
  );
  app.use((req, res, next) => {
    console.log(`${req.method} ${req.url}`);
    console.log(req.body);
    next();
  });
  await app.listen(3000);
}
bootstrap();
