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
    const { cursor, take } = CPDto;
    let { order } = CPDto;

    if (cursor) {
      try {
        const decodedCursor = Buffer.from(cursor, 'base64').toString('utf-8');
        const cusorObj = JSON.parse(decodedCursor);
        order = cusorObj.order;

        const { values } = cusorObj;

        const columns = Object.keys(values);

        const isDesc = order.some((o) => o.endsWith('DESC'));
        const comparisonOperator = isDesc ? '<' : '>';

        // 단일 컬럼
        if (columns.length === 1) {
          const column = columns[0];
          qb.where(`${qb.alias}.${column} ${comparisonOperator} :${column}`, {
            [column]: values[column],
          });
        }
        // 다중 컬럼
        else {
          const conditions = [];
          const params = {};

          // 주 비교 조건 (첫 번째 컬럼)
          const firstColumn = columns[0];
          conditions.push(
            `${qb.alias}.${firstColumn} ${comparisonOperator} :${firstColumn}`,
          );
          params[firstColumn] = values[firstColumn];

          // 첫 번째 컬럼이 같을 경우 다음 컬럼으로 비교
          for (let i = 1; i < columns.length; i++) {
            const prevColumn = columns[i - 1];
            const currentColumn = columns[i];

            conditions.push(
              `(${qb.alias}.${prevColumn} = :${prevColumn} AND ${qb.alias}.${currentColumn} ${comparisonOperator} :${currentColumn})`,
            );
            params[currentColumn] = values[currentColumn];
          }

          qb.where(conditions.join(' OR '), params);
        }
      } catch (error) {
        throw new BadRequestException(`잘못된 커서 형식: ${error.message}`);
      }
    }

    for (let i = 0; i < order.length; i++) {
      const [column, direction] = order[i].split('_');

      if (direction !== 'ASC' && direction !== 'DESC') {
        throw new BadRequestException('옳지 않은 정렬요청');
      }

      if (i === 0) {
        qb.orderBy(`${qb.alias}.${column}`, direction as 'ASC' | 'DESC');
      } else {
        qb.addOrderBy(`${qb.alias}.${column}`, direction as 'ASC' | 'DESC');
      }
    }

    qb.take(take);

    const results = await qb.getMany();

    const nextCusor =
      results.length > 0 ? this.generateNextCursor(results, order) : null;

    return { results, nextCusor };
  }

  generateNextCursor<T>(results: T[], order: string[]): string | null {
    if (results.length === 0) {
      return null;
    }

    const lastItem = results[results.length - 1];
    const values = {};

    order.forEach((columnOrder) => {
      const [column] = columnOrder.split('_');
      values[column] = lastItem[column];
    });

    const cusorObj = { values, order };
    const nextCusor = Buffer.from(JSON.stringify(cusorObj)).toString('base64');

    return nextCusor;
  }
}
