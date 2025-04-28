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
import { ApiBearerAuth } from '@nestjs/swagger';

@Controller('owner')
@ApiBearerAuth('JWT-auth')
export class OwnerController {
  constructor(private readonly ownerService: OwnerService) {}

  @Post()
  @RBAC([Permission.OWNER_MANAGEMENT])
  @UseInterceptors(TransactionInterceptor)
  async create(@Body() createOwnerDto: CreateOwnerDto, @Request() req) {
    return await this.ownerService.create(createOwnerDto, req.queryRunner);
  }

  @Get()
  @RBAC([Permission.OWNER_MANAGEMENT])
  findAll(@Query() Dto: CursorPagenationDto) {
    return this.ownerService.findAll(Dto);
  }

  @Get(':id')
  @RBAC([Permission.OWNER_MANAGEMENT])
  findOne(@Param('id') id: string) {
    return this.ownerService.findOne(+id);
  }

  @Patch(':id')
  @RBAC([Permission.OWNER_MANAGEMENT])
  update(
    @Param('id') id: string,
    @Body() updateOwnerDto: UpdateOwnerDto,
    @Request() req,
  ) {
    return this.ownerService.update(+id, updateOwnerDto, req.queryRunner);
  }

  @Delete(':id')
  @RBAC([Permission.OWNER_MANAGEMENT])
  remove(@Param('id') id: string) {
    return this.ownerService.remove(+id);
  }
}
