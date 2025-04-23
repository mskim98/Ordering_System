import { Reflector } from '@nestjs/core';
import { Permission } from '../permission/permission';

export const RBAC = Reflector.createDecorator<Permission[]>();
