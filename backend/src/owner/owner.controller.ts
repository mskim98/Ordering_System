import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  UseInterceptors,
  Request,
  Query,
} from '@nestjs/common';
import { OwnerService } from './owner.service';
import { CreateOwnerDto } from './dto/create-owner.dto';
import { UpdateOwnerDto } from './dto/update-owner.dto';
import { RBAC } from 'src/auth/decorator/rbac.decorator';
import { Permission } from 'src/auth/permission/permission';
import { TransactionInterceptor } from 'src/common/interceptor/transaction.interceptor';
import { CursorPagenationDto } from 'src/common/dto/cursor-pagenation.dto';

@Controller('owner')
export class OwnerController {
  constructor(private readonly ownerService: OwnerService) {}

  @Post()
  @RBAC([Permission.OWNER_HANDLE])
  @UseInterceptors(TransactionInterceptor)
  async create(@Body() createOwnerDto: CreateOwnerDto, @Request() req) {
    return await this.ownerService.create(createOwnerDto, req.queryRunner);
  }

  @Get()
  @RBAC([Permission.OWNER_HANDLE])
  findAll(@Query() Dto: CursorPagenationDto) {
    return this.ownerService.findAll(Dto);
  }

  @Get(':id')
  @RBAC([Permission.OWNER_HANDLE])
  findOne(@Param('id') id: string) {
    return this.ownerService.findOne(+id);
  }

  @Patch(':id')
  @RBAC([Permission.OWNER_HANDLE])
  update(
    @Param('id') id: string,
    @Body() updateOwnerDto: UpdateOwnerDto,
    @Request() req,
  ) {
    return this.ownerService.update(+id, updateOwnerDto, req.queryRunner);
  }

  @Delete(':id')
  @RBAC([Permission.OWNER_HANDLE])
  remove(@Param('id') id: string) {
    return this.ownerService.remove(+id);
  }
}
