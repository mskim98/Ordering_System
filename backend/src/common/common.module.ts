import { Module, Global } from '@nestjs/common';
import { CommonService } from './common.service';

@Global()
@Module({
  imports: [],
  providers: [CommonService],
  exports: [CommonService],
})
export class CommonModule {}
