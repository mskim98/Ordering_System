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

@Controller('order')
export class OrderController {
  constructor(private readonly orderService: OrderService) {}

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
}
