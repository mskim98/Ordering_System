import { Role } from 'src/user/entities/user.entity';

export enum Permission {
  USER_REGISTER = 'user_register', // 유저 가입
  USER_READALL = 'user_readall', // 전체유저 읽기
  USER_READONE = 'user_readone', // 개별유저 읽기
  USER_UPDATE = 'user_update', // 유저 수정
  USER_DELETE = 'user_delete', // 유저 삭제
  STORE_CREATE = 'store_create', // 점포 생성
  STORE_READ = 'store_read', // 점포 읽기
  STORE_UPDATE = 'store_update', // 점포 수정
  STORE_DELETE = 'store_delete', // 점포 삭제
  ORDER_READ = 'order_read', // 발주 읽기
  ORDER_WRITE = 'order_write', // 발주 쓰기
  LOGISTICS_MANAGEMENT = 'logistics_management', // 물류/센터 관리
  SALES_READ = 'sales_read', // 매출 읽기
  SALES_WRITE = 'sales_write', // 매출 쓰기
  OWNER_HANDLE = 'owner_handle', // 점포 - 점주 관리
  ADMIN_ITEM = 'admin_item', // 품목 관리
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
