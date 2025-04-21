import { Reflector } from '@nestjs/core';
import { Role } from 'src/user/entities/user.entity';

export enum Permission {
  USER_REGISTER = 'user_register', // 유저 가입
  ORDER_READ = 'order_read', // 발주 읽기
  ORDER_WRITE = 'order_write', // 발주 쓰기
  PRODUCT_MANAGEMENT = 'product_management', // 품목 관리
  LOGISTICS_MANAGEMENT = 'logistics_management', // 물류/센터 관리
  STORE_MANAGEMENT = 'store_management', // 점포 관리
  SALES_READ = 'sales_read', // 매출 읽기
  SALES_WRITE = 'sales_write', // 매출 쓰기
}

// 각 역할별 권한 매핑
export const rolePermissions = {
  [Role.admin]: Object.values(Permission), // 모든 권한
  [Role.owner]: [
    Permission.ORDER_READ,
    Permission.ORDER_WRITE,
    Permission.SALES_READ,
    Permission.SALES_WRITE,
  ],
  [Role.partner]: [Permission.ORDER_READ],
};

export const RBAC = Reflector.createDecorator<Permission[]>();
