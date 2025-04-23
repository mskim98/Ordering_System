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

      const newItem = await queryRunner.manager.save(Item, {
        ...createItemDto,
      });

      return await queryRunner.manager.findOne(Item, {
        where: { id: newItem.id },
      });
    } catch (e) {
      throw new BadRequestException('품목 생성에 실패했습니다.');
    }
  }

  async findAll(Dto: CursorPagenationDto) {
    try {
      const qb = this.itemRepository.createQueryBuilder('item');

      const { results, nextCusor } =
        await this.commonService.CursorPagenationParamsQb(qb, Dto);

      return { results, nextCusor };
    } catch (e) {
      throw new BadRequestException('품목 조회에 실패했습니다.');
    }
  }

  async findOne(id: number) {
    let item;
    try {
      item = await this.itemRepository.findOne({
        where: { id },
      });
    } catch (e) {
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

      await queryRunner.manager.update(Item, { id }, { ...updateItemDto });

      return await queryRunner.manager.findOne(Item, {
        where: { id },
      });
    } catch (e) {
      throw new BadRequestException('품목 수정에 실패했습니다.');
    }
  }

  async remove(id: number) {
    try {
      const item = await this.findOne(id);
      await this.itemRepository.delete(id);
      return { message: '품목 삭제 완료' };
    } catch (e) {
      throw new BadRequestException('품목 삭제에 실패했습니다.');
    }
  }
}
