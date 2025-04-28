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
  ParseIntPipe,
} from '@nestjs/common';
import { OrderService } from './order.service';
import { CreateOrderDto } from './dto/create-order.dto';
import { UpdateOrderDto } from './dto/update-order.dto';
import { RBAC } from 'src/auth/decorator/rbac.decorator';
import { Permission } from 'src/auth/permission/permission';
import { TransactionInterceptor } from 'src/common/interceptor/transaction.interceptor';
import { CursorPagenationDto } from 'src/common/dto/cursor-pagenation.dto';
import { ApiBearerAuth } from '@nestjs/swagger';
import { OrderScheduleService } from './order-schedule.service';

@Controller('order')
@ApiBearerAuth('JWT-auth')
export class OrderController {
  constructor(
    private readonly orderService: OrderService,
    private readonly orderScheduleService: OrderScheduleService,
  ) {}

  @Post()
  @RBAC([Permission.ORDER_WRITE])
  @UseInterceptors(TransactionInterceptor)
  async create(@Body() createOrderDto: CreateOrderDto, @Request() req) {
    return await this.orderService.create(createOrderDto, req.queryRunner);
  }

  @Get()
  @RBAC([Permission.ORDER_READ])
  async findAll(@Query() cursorDto: CursorPagenationDto) {
    return await this.orderService.findAll(cursorDto);
  }

  @Get(':id')
  @RBAC([Permission.ORDER_READ])
  async findOne(@Param('id', ParseIntPipe) id: number) {
    return await this.orderService.findOne(id);
  }

  @Patch(':id')
  @RBAC([Permission.ORDER_WRITE])
  @UseInterceptors(TransactionInterceptor)
  async update(
    @Param('id') id: number,
    @Body() updateOrderDto: UpdateOrderDto,
    @Request() req,
  ) {
    return await this.orderService.update(+id, updateOrderDto, req.queryRunner);
  }

  @Delete(':id')
  @RBAC([Permission.ORDER_MANAGEMENT])
  @UseInterceptors(TransactionInterceptor)
  async remove(@Param('id') id: number, @Request() req) {
    return await this.orderService.remove(+id, req.queryRunner);
  }

  // 테스트용 배치 수동 실행 엔드포인트
  @Post('batch/update-status')
  @RBAC([Permission.ORDER_MANAGEMENT])
  async manualUpdateStatus() {
    return await this.orderScheduleService.manuallyUpdateOrderStatus();
  }
}
