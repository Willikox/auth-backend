import { Module } from '@nestjs/common';
import { UsersService } from './users.service';
import { PrismaModule } from 'src/core/prisma/prisma.module';
import { MeController } from '../me/me.controller';
import { UsersAdminController } from 'src/admin/users.admin.controller';

@Module({
  imports: [PrismaModule],
  providers: [UsersService],
  exports: [UsersService],
  controllers: [MeController, UsersAdminController],
})
export class UsersModule {}
