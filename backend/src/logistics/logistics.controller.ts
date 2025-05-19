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
import { LogisticsService } from './logistics.service';
import { CreateLogisticDto } from './dto/create-logistic.dto';
import { UpdateLogisticDto } from './dto/update-logistic.dto';
import { RBAC } from 'src/auth/decorator/rbac.decorator';
import { Permission } from 'src/auth/permission/permission';
import { TransactionInterceptor } from 'src/common/interceptor/transaction.interceptor';
import { CursorPagenationDto } from 'src/common/dto/cursor-pagenation.dto';
import { CreateWarehouseDto } from './dto/create-warehouse.dto';
import { ApiBearerAuth } from '@nestjs/swagger';
import { UpdateWarehouseDto } from './dto/update-warehouse.dto';

@Controller('logistics')
@ApiBearerAuth('JWT-auth')
export class LogisticsController {
  constructor(private readonly logisticsService: LogisticsService) {}

  /** 물류업체 생성 */
  @Post()
  @RBAC([Permission.LOGISTICS_MANAGEMENT])
  @UseInterceptors(TransactionInterceptor)
  create(@Body() createLogisticDto: CreateLogisticDto, @Request() req) {
    return this.logisticsService.create(createLogisticDto, req.queryRunner);
  }

  /** 물류업체 조회 */
  @Get()
  @RBAC([Permission.LOGISTICS_MANAGEMENT])
  findAll(@Query() Dto: CursorPagenationDto) {
    return this.logisticsService.findAll(Dto);
  }

  /** 물류업체 상세 조회 */
  @Get(':id')
  @RBAC([Permission.LOGISTICS_MANAGEMENT])
  findOne(@Param('id') id: string) {
    return this.logisticsService.findOne(+id);
  }

  /** 물류업체 수정 */
  @Patch(':id')
  @RBAC([Permission.LOGISTICS_MANAGEMENT])
  update(
    @Param('id') id: string,
    @Body() updateLogisticDto: UpdateLogisticDto,
    @Request() req,
  ) {
    return this.logisticsService.update(
      +id,
      updateLogisticDto,
      req.queryRunner,
    );
  }

  /** 물류업체 삭제 */
  @Delete(':id')
  @RBAC([Permission.LOGISTICS_MANAGEMENT])
  @UseInterceptors(TransactionInterceptor)
  remove(@Param('id') id: string, @Request() req) {
    return this.logisticsService.remove(+id, req.queryRunner);
  }

  /** 물류업체 창고 생성 */
  @Post('warehouse/:id')
  @RBAC([Permission.LOGISTICS_MANAGEMENT])
  @UseInterceptors(TransactionInterceptor)
  createWarehouse(
    @Param('id') id: string,
    @Body() createWarehouseDto: CreateWarehouseDto,
    @Request() req,
  ) {
    return this.logisticsService.createWarehouse(
      +id,
      createWarehouseDto,
      req.queryRunner,
    );
  }

  /** 물류업체 창고 수정 */
  @Patch('warehouse/:id')
  @RBAC([Permission.LOGISTICS_MANAGEMENT])
  @UseInterceptors(TransactionInterceptor)
  updateWarehouse(
    @Param('id') id: string,
    @Body() updateWarehouseDto: UpdateWarehouseDto,
    @Request() req,
  ) {
    return this.logisticsService.updateWarehouse(
      +id,
      updateWarehouseDto,
      req.queryRunner,
    );
  }

  /** 물류업체 창고 삭제 */
  @Delete('warehouse/:id')
  @RBAC([Permission.LOGISTICS_MANAGEMENT])
  @UseInterceptors(TransactionInterceptor)
  removeWarehouse(@Param('id') id: string, @Request() req) {
    return this.logisticsService.removeWarehouse(+id, req.queryRunner);
  }
}
