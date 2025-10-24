import {
  BadRequestException,
  Body,
  Controller,
  HttpCode,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import type { Request as ExpressRequest } from 'express';
import { UsersService } from 'src/users/users.service';
import { AuditService } from 'src/audit/audit.service';
import { z } from 'zod';
import * as QRCode from 'qrcode';
import { JwtAuthGuard } from './jwt.guard';

const TotpCodeDto = z.object({
  code: z.string().min(6).max(6),
});

@Controller('me/totp')
@UseGuards(JwtAuthGuard)
export class TotpSelfController {
  constructor(
    private users: UsersService,
    private audit: AuditService,
  ) {}

  @Post('setup')
  async setup(@Req() req: ExpressRequest & { user?: any }) {
    const userId: string = req.user.userId;

    const speakeasy = await import('speakeasy');
    const secret = speakeasy.generateSecret({
      name: `SecureAuth (${req.user.email || userId})`,
      length: 20,
    });

    await this.users.setTotpTempSecret(userId, secret.base32);

    const otpauthUrl = secret.otpauth_url!;
    const qrDataUrl = await QRCode.toDataURL(otpauthUrl);

    return {
      otpauthUrl,
      qrDataUrl,
      secretBase32: secret.base32,
    };
  }

  @Post('verify')
  @HttpCode(200)
  async verify(
    @Req() req: ExpressRequest & { user?: any },
    @Body() body: unknown,
  ) {
    const parsed = TotpCodeDto.safeParse(body);
    if (!parsed.success) throw new BadRequestException(parsed.error.flatten());

    const user = await this.users.findById(req.user.userId);
    if (!user?.totTempSecret) {
      throw new BadRequestException('No TOTP setup in progress');
    }

    const speakeasy = await import('speakeasy');
    const ok = speakeasy.totp.verify({
      secret: user.totTempSecret,
      encoding: 'base32',
      token: parsed.data.code,
      window: 1,
    });

    if (!ok) throw new BadRequestException('Invalid TOTP code');

    await this.users.enableTotp(user.id, user.totTempSecret);
    await this.audit.log('user.totp.enabled', user.id);

    return { enabled: true };
  }

  @Post('disable')
  @HttpCode(200)
  async disable(@Req() req: ExpressRequest & { user?: any }) {
    const user = await this.users.findById(req.user.userId);
    if (!user) {
      throw new BadRequestException('User not found');
    }
    await this.users.disableTotp(user.id);
    await this.audit.log('user.totp.disabled', user.id);
    return { enabled: false };
  }
}
