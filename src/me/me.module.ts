import { Module } from '@nestjs/common';
import { MeController } from './me.controller';
import { AuthModule } from 'src/auth/auth.module';
import { UsersModule } from 'src/users/users.module';

@Module({
  imports: [AuthModule, UsersModule],
  controllers: [MeController],
})
export class MeModule {}
