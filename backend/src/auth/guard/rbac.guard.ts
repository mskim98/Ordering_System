import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { RBAC } from '../decorator/rbac.decorator';
import { Public } from '../decorator/public.decorator';
import { Permission, rolePermissions } from '../permission/permission';

@Injectable()
export class RBACGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    /** public 확인 */
    const isPublic = this.reflector.get(Public, context.getHandler());
    if (isPublic) {
      return true;
    }

    /** 토큰 타입 확인 */
    const request = context.switchToHttp().getRequest();
    const tokenTypeCheck = !request.user || request.user.type !== 'access';

    if (tokenTypeCheck) {
      throw new UnauthorizedException('접근 토큰 타입이 올바르지 않습니다.');
    }

    /** 요청 자원의 필요한 권한들 가져오기 */
    const requiredPermissions = this.reflector.get<Permission[]>(
      RBAC,
      context.getHandler(),
    );

    /** 권한 지정이 없으면 통과, 모든 사용자 통과 */
    if (!requiredPermissions || requiredPermissions.length === 0) {
      return true;
    }

    /** 요청한 유저의 역할 가져오기 */
    const userRole = request.user.role;

    /** 사용자 역할에 따른 권한 목록 가져오기 */
    const userPermissions = rolePermissions[userRole] || [];

    /** 모든 필요 권한이 사용자 권한에 포함되어 있는지 확인 */
    const permissionCheck = requiredPermissions.every((permission) =>
      userPermissions.includes(permission),
    );

    if (!permissionCheck) {
      throw new UnauthorizedException('권한이 없습니다.');
    }

    return permissionCheck;
  }
}
