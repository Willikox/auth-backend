import { Controller, Param, Patch, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from 'src/auth/jwt.guard';
import { AdminGuard } from 'src/auth/admin.guard';
import { UsersService } from 'src/users/users.service';

@UseGuards(JwtAuthGuard, AdminGuard)
@Controller('admin/users')
export class UsersAdminController {
  constructor(private users: UsersService) {}

  @Patch(':id/block')
  async block(@Param('id') id: string) {
    await this.users.updateById(id, { isBlocked: true });
    return { blocked: true };
  }

  @Patch(':id/unblock')
  async unblock(@Param('id') id: string) {
    await this.users.updateById(id, { isBlocked: false });
    return { blocked: false };
  }
}
