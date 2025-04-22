import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  UseInterceptors,
  ClassSerializerInterceptor,
  Query,
  Request,
} from '@nestjs/common';
import { UserService } from './user.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { RBAC, Permission } from 'src/auth/decorator/rbac.decorator';
import { CursorPagenationDto } from 'src/common/dto/cursor-pagenation.dto';

@Controller('user')
@UseInterceptors(
  ClassSerializerInterceptor,
) /** password intercepting(Entity: @toPlainOnly) */
export class UserController {
  constructor(private readonly userService: UserService) {}

  /** 유저 생성 : 관리자 권한 */
  @Post()
  @RBAC([Permission.USER_REGISTER])
  create(@Body() createUserDto: CreateUserDto) {
    return this.userService.register(createUserDto);
  }

  /** 전체 유저조회 : 관리자 권한 */
  @Get()
  @RBAC([Permission.USER_READALL])
  async findAll(@Query() Dto: CursorPagenationDto) {
    return await this.userService.findAll(Dto);
  }

  /** 개별 유저조회  */
  @Get(':id')
  @RBAC([Permission.USER_READONE])
  findOne(@Param('id') id: string, @Request() req) {
    return this.userService.findOne(+id, req.user);
  }

  /** 개별 유저 수정  */
  @Patch(':id')
  @RBAC([Permission.USER_UPDATE])
  update(@Param('id') id: string, @Body() updateUserDto: UpdateUserDto) {
    return this.userService.update(+id, updateUserDto);
  }

  /** 개별 유저 삭제 : 관리자 권한 */
  @Delete(':id')
  @RBAC([Permission.USER_DELETE])
  remove(@Param('id') id: string) {
    return this.userService.remove(+id);
  }
}
