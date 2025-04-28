import { Role } from 'src/user/entities/user.entity';

export enum Permission {
  USER_MANAGEMENT = 'user_management', // 유저 관리
  STORE_MANAGEMENT = 'store_management', // 점포 관리
  LOGISTICS_MANAGEMENT = 'logistics_management', // 물류/센터 관리
  OWNER_MANAGEMENT = 'owner_management', // 점포 - 점주 관리
  ITEM_MANAGEMENT = 'item_management', // 품목 - 품목 관리
  PRICE_MANAGEMENT = 'price_management', // 가격 관리
  ORDER_READ = 'order_read', // 발주 읽기
  ORDER_WRITE = 'order_write', // 발주 쓰기
  ORDER_MANAGEMENT = 'order_management', // 발주 관리
  SALES_READ = 'sales_read', // 매출 읽기
  SALES_WRITE = 'sales_write', // 매출 쓰기
}

// 각 역할별 권한 매핑
export const rolePermissions = {
  /** 관리자 권한 */
  [Role.admin]: Object.values(Permission),
  /** 점주 권한 */
  [Role.owner]: [
    Permission.ORDER_READ,
    Permission.ORDER_WRITE,
    Permission.SALES_READ,
    Permission.SALES_WRITE,
  ],
  /** 파트너 권한 */
  [Role.partner]: [Permission.ORDER_READ],
};
