import { Reflector } from '@nestjs/core';
import { Role } from 'src/user/entities/user.entity';

export enum Permission {
  USER_REGISTER = 'user_register', // 유저 가입
  USER_READALL = 'user_readall', // 전체유저 읽기
  USER_READONE = 'user_readone', // 개별유저 읽기
  USER_UPDATE = 'user_update', // 유저 수정
  USER_DELETE = 'user_delete', // 유저 삭제
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
  /** 관리자 권한 */
  [Role.admin]: Object.values(Permission),
  /** 점주 권한 */
  [Role.owner]: [
    Permission.USER_READONE,
    Permission.USER_UPDATE,
    Permission.ORDER_READ,
    Permission.ORDER_WRITE,
    Permission.SALES_READ,
    Permission.SALES_WRITE,
  ],
  /** 파트너 권한 */
  [Role.partner]: [Permission.ORDER_READ, Permission.USER_READONE],
};

export const RBAC = Reflector.createDecorator<Permission[]>();
