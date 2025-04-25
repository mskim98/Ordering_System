import {
  BadRequestException,
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
    }
  }

  async findAll(Dto: CursorPagenationDto) {
    try {
      const qb = this.itemRepository.createQueryBuilder('item');

      const { results, nextCusor } =
        await this.commonService.CursorPagenationParamsQb(qb, Dto);

      return { results, nextCusor };
    } catch {
      throw new BadRequestException('품목 조회에 실패했습니다.');
    }
  }

  async findOne(id: number) {
    let item;
    try {
      item = await this.itemRepository.findOne({
        where: { id },
      });
    } catch {
      throw new BadRequestException('품목 조회에 실패했습니다.');
    }

    if (!item) {
      throw new NotFoundException('존재하지 않는 품목입니다.');
    }

    return item;
  }

  async update(
    id: number,
    updateItemDto: UpdateItemDto,
    queryRunner: QueryRunner,
  ) {
    try {
      await this.findOne(id);

      const { priceIn, priceOut, margin, ...itemData } = updateItemDto;

      await queryRunner.manager.update(Item, { id }, { ...itemData });

      if (priceOut !== undefined && margin !== undefined) {
        throw new BadRequestException('마진과 출고가중 하나만 입력해주세요.');
      }

      if (
        priceIn !== undefined &&
        priceOut === undefined &&
        margin === undefined
      ) {
        await queryRunner.manager.update(
          Price,
          { item: { id } },
          {
            priceIn,
            margin: 0,
            priceOut: priceIn,
          },
        );
      }

      if (priceIn !== undefined && priceOut !== undefined) {
        const newMargin = ((priceOut - priceIn) / priceOut) * 100;
        await queryRunner.manager.update(
          Price,
          { item: { id } },
          { priceIn, priceOut, margin: newMargin },
        );
      }

      if (priceIn !== undefined && margin !== undefined) {
        const newPriceOut = priceIn * (1 + margin / 100);
        await queryRunner.manager.update(
          Price,
          { item: { id } },
          { priceIn, priceOut: newPriceOut, margin },
        );
      }

      return await queryRunner.manager.findOne(Item, {
        where: { id },
        relations: ['price'],
      });
    } catch (e) {
      if (e instanceof NotFoundException) {
        throw e;
      }
      if (e instanceof BadRequestException) {
        throw e;
      }
    }
  }

  async remove(id: number, queryRunner: QueryRunner) {
    try {
      await this.findOne(id);
      await queryRunner.manager.delete(Item, id);
      return { message: '품목 삭제 완료' };
    } catch (e) {
      if (e instanceof NotFoundException) {
        throw e;
      }
      throw new BadRequestException('품목 삭제에 실패했습니다.');
    }
  }
}
