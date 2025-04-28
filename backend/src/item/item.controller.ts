import {
  Controller,
  Get,
  Post,
  Patch,
  Param,
  Delete,
  UseInterceptors,
  Request,
  Query,
  Body,
} from '@nestjs/common';
import { ItemService } from './item.service';
import { CreateItemDto } from './dto/create-item.dto';
import { UpdateItemDto } from './dto/update-item.dto';
import { RBAC } from 'src/auth/decorator/rbac.decorator';
import { Permission } from 'src/auth/permission/permission';
import { TransactionInterceptor } from 'src/common/interceptor/transaction.interceptor';
import { CursorPagenationDto } from 'src/common/dto/cursor-pagenation.dto';
import { SetItemLogisticsDto } from './dto/set-item-logistics.dto';

@Controller('item')
export class ItemController {
  constructor(private readonly itemService: ItemService) {}

  @Post()
  @RBAC([Permission.ITEM_MANAGEMENT])
  @UseInterceptors(TransactionInterceptor)
  async create(@Body() createItemDto: CreateItemDto, @Request() req) {
    return await this.itemService.create(createItemDto, req.queryRunner);
  }

  /** 전체 품목 조회 */
  @Get()
  @RBAC([Permission.ITEM_MANAGEMENT])
  async findAll(@Query() DTO: CursorPagenationDto) {
    return await this.itemService.findAll(DTO);
  }

  /** 품목 상세 조회 */
  @Get(':id')
  @RBAC([Permission.ITEM_MANAGEMENT])
  async findOne(@Param('id') id: string) {
    return await this.itemService.findOne(+id);
  }

  /** 품목 수정 */
  @Patch(':id')
  @RBAC([Permission.ITEM_MANAGEMENT])
  @UseInterceptors(TransactionInterceptor)
  async update(
    @Param('id') id: string,
    @Body() updateItemDto: UpdateItemDto,
    @Request() req,
  ) {
    return await this.itemService.update(+id, updateItemDto, req.queryRunner);
  }

  /** 품목 삭제 */
  @Delete(':id')
  @RBAC([Permission.ITEM_MANAGEMENT])
  @UseInterceptors(TransactionInterceptor)
  async remove(@Param('id') id: string, @Request() req) {
    return await this.itemService.remove(+id, req.queryRunner);
  }

  @Post('logistics')
  @RBAC([Permission.ITEM_MANAGEMENT])
  @UseInterceptors(TransactionInterceptor)
  async setLogistics(@Body() Dto: SetItemLogisticsDto, @Request() req) {
    return await this.itemService.setLogistics(Dto, req.queryRunner);
  }
}
