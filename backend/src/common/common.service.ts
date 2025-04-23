import { BadRequestException, Injectable } from '@nestjs/common';
import { SelectQueryBuilder } from 'typeorm';
import { CursorPagenationDto } from './dto/cursor-pagenation.dto';

@Injectable()
export class CommonService {
  constructor() {}

  async CursorPagenationParamsQb<T>(
    qb: SelectQueryBuilder<T>,
    CPDto: CursorPagenationDto,
  ) {
    let { cursor, order, take } = CPDto;

    if (cursor) {
      const decodedCursor = Buffer.from(cursor, 'base64').toString('utf-8');
      const cusorObj = JSON.parse(decodedCursor);
      order = cusorObj.order;

      const { values } = cusorObj;

      const columns = Object.keys(values);

      /** 비교 연산 설정 */
      const comparisonOperator = order.some((o) => o.endsWith('DESC'))
        ? '<'
        : '>';

      /** 비교할 column 설정 */
      const whereConditions = columns.map((c) => `${qb.alias}.${c}`).join(', ');

      /** 비교할 값 설정 */
      const whereParams = columns.map((c) => `:${c}`).join(',');

      qb.where(
        `(${whereConditions}) ${comparisonOperator} (${whereParams})`,
        values,
      );
    }

    for (let i = 0; i < order.length; i++) {
      const [column, direction] = order[i].split('_');

      if (direction !== 'ASC' && direction !== 'DESC') {
        throw new BadRequestException('옳지 않은 정렬요청');
      }

      if (i === 0) {
        qb.orderBy(`${qb.alias}.${column}`, direction);
      } else {
        qb.addOrderBy(`${qb.alias}.${column}`, direction);
      }
    }

    qb.take(take);

    const results = await qb.getMany();

    const nextCusor = this.generateNextCursor(results, order);

    return { qb, nextCusor };
  }

  generateNextCursor<T>(results: T[], order: string[]): string | null {
    if (results.length === 0) {
      return null;
    } else {
      const lastItem = results[results.length - 1];

      const values = {};

      order.forEach((columnOrder) => {
        const [column] = columnOrder.split('_');
        values[column] = lastItem[column];
      });

      const cusorObj = { values, order };
      //** base64 encoding */
      const nextCusor = Buffer.from(JSON.stringify(cusorObj)).toString(
        'base64',
      );
      return nextCusor;
    }
  }
}
