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
} from '@nestjs/common';
import { StoreService } from './store.service';
import { CreateStoreDto } from './dto/create-store.dto';
import { UpdateStoreDto } from './dto/update-store.dto';
import { RBAC } from 'src/auth/decorator/rbac.decorator';
import { Permission } from 'src/auth/permission/permission';
import { TransactionInterceptor } from 'src/common/interceptor/transaction.interceptor';

@Controller('store')
export class StoreController {
  constructor(private readonly storeService: StoreService) {}

  @Post()
  @RBAC([Permission.STORE_CREATE])
  @UseInterceptors(TransactionInterceptor)
  create(@Body() createStoreDto: CreateStoreDto, @Request() req) {
    return this.storeService.create(createStoreDto, req.queryRunner);
  }

  @Get()
  findAll() {
    return this.storeService.findAll();
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.storeService.findOne(+id);
  }

  @Patch(':id')
  update(@Param('id') id: string, @Body() updateStoreDto: UpdateStoreDto) {
    return this.storeService.update(+id, updateStoreDto);
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.storeService.remove(+id);
  }
}
