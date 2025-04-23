import { BadRequestException, Injectable } from '@nestjs/common';
import { CreateStoreDto } from './dto/create-store.dto';
import { UpdateStoreDto } from './dto/update-store.dto';
import { QueryRunner, Repository } from 'typeorm';
import { Store } from './entities/store.entity';
import { InjectRepository } from '@nestjs/typeorm';

@Injectable()
export class StoreService {
  constructor(
    @InjectRepository(Store)
    private readonly storeRepository: Repository<Store>,
  ) {}
  async create(createStoreDto: CreateStoreDto, queryRunner: QueryRunner) {
    try {
      const name = createStoreDto.name;
      const store = await queryRunner.manager.findOne(Store, {
        where: { name },
      });

      if (store) {
        throw new Error('existing');
      }

      const newStore = await queryRunner.manager.save(Store, {
        ...createStoreDto,
      });

      return newStore;
    } catch (e) {
      if (e.message === 'exisring') {
        throw new BadRequestException('이미 존재하는 점포입니다.');
      }
      throw new BadRequestException('점포 생성 실패');
    }
  }

  findAll() {
    return `This action returns all store`;
  }

  findOne(id: number) {
    return `This action returns a #${id} store`;
  }

  update(id: number, updateStoreDto: UpdateStoreDto) {
    return `This action updates a #${id} store`;
  }

  remove(id: number) {
    return `This action removes a #${id} store`;
  }
}
