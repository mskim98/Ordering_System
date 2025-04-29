import { SetMetadata } from '@nestjs/common';
import { Permission } from '../permission/permission';

export const RBAC_KEY = 'permissions';
export const RBAC = (permissions: Permission[]) =>
  SetMetadata(RBAC_KEY, permissions);
