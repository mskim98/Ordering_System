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
import { StoreService } from './store.service';
import { CreateStoreDto } from './dto/create-store.dto';
import { UpdateStoreDto } from './dto/update-store.dto';
import { RBAC } from 'src/auth/decorator/rbac.decorator';
import { Permission } from 'src/auth/permission/permission';
import { TransactionInterceptor } from 'src/common/interceptor/transaction.interceptor';
import { CursorPagenationDto } from 'src/common/dto/cursor-pagenation.dto';

@Controller('store')
export class StoreController {
  constructor(private readonly storeService: StoreService) {}

  /** 점포 생성 */
  @Post()
  @RBAC([Permission.STORE_CREATE])
  @UseInterceptors(TransactionInterceptor)
  create(@Body() createStoreDto: CreateStoreDto, @Request() req) {
    return this.storeService.create(createStoreDto, req.queryRunner);
  }

  /** 전체 점포 목록 조회 */
  @Get()
  @RBAC([Permission.STORE_READ])
  findAll(@Query() Dto: CursorPagenationDto) {
    return this.storeService.findAll(Dto);
  }

  /** 점포 상세 조회 */
  @Get(':id')
  @RBAC([Permission.STORE_READ])
  findOne(@Param('id') id: string) {
    return this.storeService.findOne(+id);
  }

  /** 점포 정보 업데이트 */
  @Patch(':id')
  @RBAC([Permission.STORE_UPDATE])
  @UseInterceptors(TransactionInterceptor)
  async update(
    @Param('id') id: string,
    @Body() updateStoreDto: UpdateStoreDto,
    @Request() req,
  ) {
    return this.storeService.update(+id, updateStoreDto, req.queryRunner);
  }

  /** 점포 삭제 */
  @Delete(':id')
  @RBAC([Permission.STORE_DELETE])
  @UseInterceptors(TransactionInterceptor)
  remove(@Param('id') id: string, @Request() req) {
    return this.storeService.remove(+id, req.queryRunner);
  }
}
