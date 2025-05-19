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

  /** 주문 생성 */
  @Post()
  @RBAC([Permission.ORDER_WRITE])
  @UseInterceptors(TransactionInterceptor)
  async create(@Body() createOrderDto: CreateOrderDto, @Request() req) {
    return await this.orderService.createWithRetry(
      createOrderDto,
      req.queryRunner,
    );
  }

  /** 전체 주문 목록 조회 */
  @Get()
  @RBAC([Permission.ORDER_MANAGEMENT])
  async findAll(@Query() cursorDto: CursorPagenationDto) {
    return await this.orderService.findAll(cursorDto);
  }

  /** 본인 주문 목록 조회 */
  @Get('my')
  @RBAC([Permission.ORDER_READ])
  async findMy(@Query() cursorDto: CursorPagenationDto, @Request() req) {
    const userId = req.user?.sub;
    return await this.orderService.findMy(cursorDto, userId);
  }

  /** 특정 주문 조회 */
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
}
