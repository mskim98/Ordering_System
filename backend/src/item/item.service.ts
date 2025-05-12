import {
  BadRequestException,
  ConflictException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { CreateItemDto } from './dto/create-item.dto';
import { UpdateItemDto } from './dto/update-item.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, QueryRunner } from 'typeorm';
import { Item } from './entities/item.entity';
import { CommonService } from 'src/common/common.service';
import { CursorPagenationDto } from 'src/common/dto/cursor-pagenation.dto';
import { Price } from './entities/price.entity';
import { SetItemLogisticsDto } from './dto/set-item-logistics.dto';
import { Logistics } from 'src/logistics/entities/logistics.entity';

@Injectable()
export class ItemService {
  constructor(
    @InjectRepository(Item)
    private itemRepository: Repository<Item>,
    private readonly commonService: CommonService,
  ) {}

  async create(createItemDto: CreateItemDto, queryRunner: QueryRunner) {
    try {
      const item = await queryRunner.manager.findOne(Item, {
        where: { name: createItemDto.name },
      });

      if (item) {
        throw new BadRequestException('이미 존재하는 품목입니다.');
      }

      const { priceIn, margin, priceOut, ...itemData } = createItemDto;
      if (margin && priceOut) {
        throw new BadRequestException('마진과 출고가중 하나만 입력해주세요.');
      }

      const newItem = await queryRunner.manager.save(Item, {
        ...itemData,
      });

      /** 입고가만 있는 경우 */
      if (
        priceIn !== undefined &&
        margin === undefined &&
        priceOut === undefined
      ) {
        const newPrice = queryRunner.manager.create(Price, {
          item: newItem,
          priceIn,
          priceOut: priceIn,
          margin: 0,
        });
        await queryRunner.manager.save(Price, newPrice);
      }

      /* 입고가와 출고가가 있는 경우 */
      if (priceIn !== undefined && priceOut !== undefined) {
        const calculatedMargin = ((priceOut - priceIn) / priceOut) * 100;
        const newPrice = queryRunner.manager.create(Price, {
          item: newItem,
          priceIn,
          priceOut,
          margin: calculatedMargin,
        });
        await queryRunner.manager.save(Price, newPrice);
      }

      /** 입고가와 마진이 있는 경우 */
      if (priceIn !== undefined && margin !== undefined) {
        const calculatedPriceOut = priceIn * (1 + margin / 100);
        const newPrice = queryRunner.manager.create(Price, {
          item: newItem,
          priceIn,
          priceOut: calculatedPriceOut,
          margin,
        });
        await queryRunner.manager.save(Price, newPrice);
      }

      return await queryRunner.manager.findOne(Item, {
        where: { id: newItem.id },
        relations: ['price'],
      });
    } catch (e) {
      if (e instanceof BadRequestException) {
        throw e;
      }
      throw new BadRequestException('품목 생성에 실패했습니다.');
    }
  }

  async findAll(Dto: CursorPagenationDto) {
    try {
      const qb = this.itemRepository
        .createQueryBuilder('item')
        .leftJoinAndSelect('item.price', 'price')
        .leftJoinAndSelect('item.logistics', 'logistics')
        .select([
          'item.id',
          'item.name',
          'item.useCondition',
          'item.specification',
          'item.type',
          'price.priceOut',
          'logistics.name',
        ]);
      return await this.commonService.CursorPagenationParamsQb(qb, Dto);
    } catch (error) {
      throw new BadRequestException(
        `품목 조회에 실패했습니다: ${error.message}`,
      );
    }
  }

  async findOne(id: number) {
    try {
      const item = await this.itemRepository.exists({
        where: { id },
      });

      if (!item) {
        throw new NotFoundException('not exist');
      }

      return await this.itemRepository
        .createQueryBuilder('item')
        .leftJoinAndSelect('item.price', 'price')
        .leftJoinAndSelect('item.logistics', 'logistics')
        .select([
          'item.id',
          'item.name',
          'item.useCondition',
          'item.specification',
          'item.type',
          'price.priceOut',
          'logistics.name',
        ])
        .where('item.id = :id', { id })
        .getOne();
    } catch (error) {
      if (error.message === 'not exist') {
        throw new NotFoundException('존재하지 않는 품목입니다.');
      }
      throw new BadRequestException('품목 조회에 실패했습니다.');
    }
  }

  async update(
    id: number,
    updateItemDto: UpdateItemDto,
    queryRunner: QueryRunner,
  ) {
    try {
      const item = await queryRunner.manager
        .createQueryBuilder(Item, 'item')
        .leftJoinAndSelect('item.price', 'price')
        .where('item.id = :id', { id })
        .setLock('pessimistic_write')
        .getOne();

      if (!item) {
        throw new NotFoundException(`품목 ID ${id}를 찾을 수 없습니다`);
      }

      const { priceIn, priceOut, margin, ...itemData } = updateItemDto;

      Object.assign(item, itemData);
      await queryRunner.manager.save(item);

      if (priceOut !== undefined && margin !== undefined) {
        throw new BadRequestException('마진과 출고가중 하나만 입력해주세요.');
      }

      if (
        priceIn !== undefined &&
        priceOut === undefined &&
        margin === undefined
      ) {
        item.price.priceIn = priceIn;
        item.price.margin = 0;
        item.price.priceOut = priceIn;
        await queryRunner.manager.save(item.price);
      }

      if (priceIn !== undefined && priceOut !== undefined) {
        const newMargin = ((priceOut - priceIn) / priceOut) * 100;
        item.price.priceIn = priceIn;
        item.price.priceOut = priceOut;
        item.price.margin = newMargin;
        await queryRunner.manager.save(item.price);
      }

      if (priceIn !== undefined && margin !== undefined) {
        const newPriceOut = priceIn * (1 + margin / 100);
        item.price.priceIn = priceIn;
        item.price.priceOut = newPriceOut;
        item.price.margin = margin;
        await queryRunner.manager.save(item.price);
      }

      return await queryRunner.manager.findOne(Item, {
        where: { id },
        relations: ['price'],
      });
    } catch (e) {
      if (e.code === '40P01') {
        throw new ConflictException(
          '데이터 충돌이 발생했습니다. 다시 시도해주세요.',
        );
      }
      if (e instanceof NotFoundException) {
        throw e;
      }
      if (e instanceof BadRequestException) {
        throw e;
      }
      throw new BadRequestException('품목 수정에 실패했습니다.');
    }
  }

  async remove(id: number, queryRunner: QueryRunner) {
    try {
      // 먼저 항목이 존재하는지 확인
      const item = await queryRunner.manager.findOne(Item, {
        where: { id },
      });

      if (!item) {
        throw new NotFoundException('존재하지 않는 품목입니다.');
      }

      // 품목 삭제 시도 (cascade로 price도 자동 삭제됨)
      const result = await queryRunner.manager.delete(Item, id);

      if (result.affected === 0) {
        throw new Error('품목 삭제 실패');
      }

      return { message: '품목 삭제 완료' };
    } catch (e) {
      if (e instanceof NotFoundException) {
        throw e;
      }
      // 오류 메시지 포함
      console.error('삭제 오류:', e);
      throw new BadRequestException(`품목 삭제에 실패했습니다: ${e.message}`);
    }
  }

  async setLogistics(Dto: SetItemLogisticsDto, queryRunner: QueryRunner) {
    try {
      const item = await queryRunner.manager.findOne(Item, {
        where: { id: Dto.itemId },
      });

      if (!item) {
        throw new NotFoundException('not exist');
      }

      const logistics = await queryRunner.manager.findOne(Logistics, {
        where: { id: Dto.logisticsId },
      });

      if (!logistics) {
        throw new NotFoundException('not exist');
      }

      await queryRunner.manager.update(
        Item,
        { id: Dto.itemId },
        {
          logistics: { id: Dto.logisticsId },
        },
      );

      return { message: '물류업체 설정 완료' };
    } catch (e) {
      if (e.message === 'not exist') {
        throw new NotFoundException('존재하지 않는 품목 또는 물류업체입니다.');
      }
      throw new BadRequestException('물류업체 설정에 실패했습니다.');
    }
  }
}
