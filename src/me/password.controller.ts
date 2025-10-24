import {
  BadRequestException,
  Body,
  Controller,
  Patch,
  Req,
  UseGuards,
} from '@nestjs/common';
import { JwtAuthGuard } from 'src/auth/jwt.guard';
import { UsersService } from 'src/users/users.service';
import * as bcrypt from 'bcrypt';
import { z } from 'zod';
import type { Request as ExpressRequest } from 'express';

const ChangePwdDto = z.object({
  currentPassword: z.string().min(8),
  newPassword: z.string().min(8),
});

type JwtRequest = ExpressRequest & { user: { userId: string; email: string } };

@UseGuards(JwtAuthGuard)
@Controller('me')
export class MePasswordController {
  constructor(private users: UsersService) {}

  @Patch('password')
  async change(@Body() body: unknown, @Req() req: JwtRequest) {
    const parsed = ChangePwdDto.safeParse(body);
    if (!parsed.success) throw new BadRequestException(parsed.error.flatten());

    const user = await this.users.findById(req.user.userId);
    if (!user?.passwordHash) {
      throw new BadRequestException('No password set for this account');
    }
    const ok = await bcrypt.compare(
      parsed.data.currentPassword,
      user.passwordHash,
    );
    if (!ok) throw new BadRequestException('Current password is wrong');

    await this.users.setPassword(user.id, parsed.data.newPassword);
    return { changed: true };
  }
}
