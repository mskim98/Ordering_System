import { Module } from '@nestjs/common';
import { UserModule } from './user/user.module';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule, ConfigService } from '@nestjs/config';
import * as Joi from 'joi';
import { envVaribaleKeys } from './common/const/env.const';
import { User } from './user/entities/user.entity';
import { AuthModule } from './auth/auth.module';

@Module({
  imports: [
    /** env 검증 파트 */
    ConfigModule.forRoot({
      isGlobal: true,
      validationSchema: Joi.object({
        ENV: Joi.string().valid('dev', 'prod').required(),
        DB_TYPE: Joi.string().valid('postgres').required(),
        DB_HOST: Joi.string().required(),
        DB_PORT: Joi.number().required(),
        DB_USERNAME: Joi.string().required(),
        DB_PASSWORD: Joi.string().required(),
        DB_DATABASE: Joi.string().required(),
        HASH_ROUNDS: Joi.number().required(),
        ACCESS_TOKEN_SECRET: Joi.string().required(),
        REFRESH_TOKEN_SECRET: Joi.string().required(),
      }),
    }),
    /** db 연결 파트 */
    TypeOrmModule.forRootAsync({
      useFactory: (configService: ConfigService) => ({
        type: configService.get<string>(envVaribaleKeys.dbType) as 'postgres',
        host: configService.get<string>(envVaribaleKeys.dbHost),
        port: +configService.get<number>(envVaribaleKeys.dbPort),
        username: configService.get<string>(envVaribaleKeys.dbUsername),
        password: configService.get<string>(envVaribaleKeys.dbPassword),
        database: configService.get<string>(envVaribaleKeys.dbDatabase),
        entities: [User],
        synchronize: true,
      }),
      inject: [ConfigService],
    }),
    /** 사용 모듈 */
    UserModule,
    AuthModule,
  ],
})
export class AppModule {}
