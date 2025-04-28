import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { UserModule } from './user/user.module';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule, ConfigService } from '@nestjs/config';
import * as Joi from 'joi';
import { envVaribaleKeys } from './common/const/env.const';
import { User } from './user/entities/user.entity';
import { AuthModule } from './auth/auth.module';
import { TokenAuthanticator } from './auth/middleware/tokenAuthanticator.middleware';
import { APP_GUARD, APP_INTERCEPTOR } from '@nestjs/core';
import { RBACGuard } from './auth/guard/rbac.guard';
import { StoreModule } from './store/store.module';
import { Store } from './store/entities/store.entity';
import { TransactionInterceptor } from './common/interceptor/transaction.interceptor';
import { TimeoutInterceptor } from './common/interceptor/timeout.interceptor';
import { CommonModule } from './common/common.module';
import { OwnerModule } from './owner/owner.module';
import { Owner } from './owner/entities/owner.entity';
import { ItemModule } from './item/item.module';
import { Item } from './item/entities/item.entity';
import { Price } from './item/entities/price.entity';
import { LogisticsModule } from './logistics/logistics.module';
import { Logistics } from './logistics/entities/logistics.entity';
import { Warehouse } from './logistics/entities/warehouse.entity';
import { OrderModule } from './order/order.module';
import { Order } from './order/entities/order.entity';
import { OrderItem } from './order/entities/orderItem.entity';

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
        entities: [
          User,
          Store,
          Owner,
          Item,
          Price,
          Logistics,
          Warehouse,
          Order,
          OrderItem,
        ],
        synchronize: true,
      }),
      inject: [ConfigService],
    }),
    /** 사용 모듈 */
    UserModule,
    AuthModule,
    StoreModule,
    CommonModule,
    OwnerModule,
    ItemModule,
    LogisticsModule,
    OrderModule,
  ],
  /** 모든 요청에 대해서 AuthGuard를 적용 */
  providers: [
    {
      provide: APP_GUARD,
      useClass: RBACGuard,
    },
    {
      provide: APP_INTERCEPTOR,
      useClass: TimeoutInterceptor,
    },
    {
      provide: APP_INTERCEPTOR,
      useClass: TransactionInterceptor,
    },
  ],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(TokenAuthanticator).forRoutes('*');
  }
}
