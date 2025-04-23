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
import { ItemService } from './item.service';
import { CreateItemDto } from './dto/create-item.dto';
import { UpdateItemDto } from './dto/update-item.dto';
import { RBAC } from 'src/auth/decorator/rbac.decorator';
import { Permission } from 'src/auth/permission/permission';
import { TransactionInterceptor } from 'src/common/interceptor/transaction.interceptor';
import { CursorPagenationDto } from 'src/common/dto/cursor-pagenation.dto';

@Controller('item')
export class ItemController {
  constructor(private readonly itemService: ItemService) {}

  @Post()
  @RBAC([Permission.ADMIN_ITEM])
  @UseInterceptors(TransactionInterceptor)
  async create(@Body() createItemDto: CreateItemDto, @Request() req) {
    return await this.itemService.create(createItemDto, req.queryRunner);
  }

  @Get()
  @RBAC([Permission.ADMIN_ITEM])
  async findAll(@Query() DTO: CursorPagenationDto) {
    return await this.itemService.findAll(DTO);
  }

  @Get(':id')
  @RBAC([Permission.ADMIN_ITEM])
  async findOne(@Param('id') id: string) {
    return await this.itemService.findOne(+id);
  }

  @Patch(':id')
  @RBAC([Permission.ADMIN_ITEM])
  async update(
    @Param('id') id: string,
    @Body() updateItemDto: UpdateItemDto,
    @Request() req,
  ) {
    return await this.itemService.update(+id, updateItemDto, req.queryRunner);
  }

  @Delete(':id')
  @RBAC([Permission.ADMIN_ITEM])
  async remove(@Param('id') id: string) {
    return await this.itemService.remove(+id);
  }
}
