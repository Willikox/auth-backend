import {
  BadRequestException,
  Body,
  Controller,
  HttpCode,
  Ip,
  Post,
  Req,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginDto, RefreshDto, RegisterDto } from './dto';
import type { Request as ExpressRequest } from 'express';
import z from 'zod';
import { Throttle } from '@nestjs/throttler';

const TotpLoginDto = z.object({
  ticket: z.string().min(3),
  code: z.string().min(6).max(6),
});

const ForgotDto = z.object({
  email: z.string().email(),
});

const ResetDto = z.object({
  token: z.string().min(10),
  newPassword: z.string().min(8),
});

@Controller('auth')
export class AuthController {
  constructor(private auth: AuthService) {}

  @Post('register')
  async register(
    @Body() body: unknown,
    @Ip() ip: string,
    @Req() req: ExpressRequest,
  ) {
    const parsed = RegisterDto.safeParse(body);
    if (!parsed.success) throw new BadRequestException(parsed.error.flatten());
    const { email, password } = parsed.data;

    const userAgent: string | undefined = req.get?.('user-agent') ?? undefined;

    const user = await this.auth.register(email, password, ip, userAgent);
    return { id: user.id, email: user.email };
  }

  @Post('login')
  @HttpCode(200)
  @Throttle({ default: { ttl: 60, limit: 5 } })
  async login(
    @Body() body: unknown,
    @Ip() ip: string,
    @Req() req: ExpressRequest,
  ) {
    const parsed = LoginDto.safeParse(body);
    if (!parsed.success) throw new BadRequestException(parsed.error.flatten());
    const { email, password } = parsed.data;

    const userAgent: string | undefined = req.get?.('user-agent') ?? undefined;
    return this.auth.login(email, password, ip, userAgent);
  }

  @Post('refresh')
  @HttpCode(200)
  async refresh(
    @Body() body: unknown,
    @Ip() ip: string,
    @Req() req: ExpressRequest,
  ) {
    const parsed = RefreshDto.safeParse(body);
    if (!parsed.success) throw new BadRequestException(parsed.error.flatten());

    const userAgent: string | undefined = req.get?.('user-agent') ?? undefined;

    return this.auth.refresh(parsed.data.refreshToken, ip, userAgent);
  }

  @Post('logout')
  @HttpCode(204)
  async logout(
    @Body() body: unknown,
    @Ip() ip: string,
    @Req() req: ExpressRequest,
  ) {
    const parsed = RefreshDto.safeParse(body);
    if (!parsed.success) throw new BadRequestException(parsed.error.flatten());

    const userAgent = req.get?.('user-agent') ?? undefined;
    await this.auth.logout(parsed.data.refreshToken, ip, userAgent);
    return;
  }

  @Post('totp/verify')
  @HttpCode(200)
  @Throttle({ default: { ttl: 60, limit: 6 } })
  async verifyTotpForLogin(
    @Body() body: unknown,
    @Ip() ip: string,
    @Req() req: ExpressRequest,
  ) {
    const parsed = TotpLoginDto.safeParse(body);
    if (!parsed.success) throw new BadRequestException(parsed.error.flatten());

    const userAgent = req.get?.('user-agent') ?? undefined;
    const { ticket, code } = parsed.data;

    return this.auth.verifyTotpLogin(ticket, code, ip, userAgent);
  }

  @Post('forgot')
  @HttpCode(200)
  @Throttle({ default: { ttl: 60, limit: 3 } })
  async forgot(
    @Body() body: unknown,
    @Ip() ip: string,
    @Req() req: ExpressRequest,
  ) {
    const parsed = ForgotDto.safeParse(body);
    if (!parsed.success) throw new BadRequestException(parsed.error.flatten());
    const ua = req.get?.('user-agent') ?? undefined;
    return this.auth.forgot(parsed.data.email, ip, ua);
  }

  @Post('reset')
  @HttpCode(200)
  async reset(
    @Body() body: unknown,
    @Ip() ip: string,
    @Req() req: ExpressRequest,
  ) {
    const parsed = ResetDto.safeParse(body);
    if (!parsed.success) throw new BadRequestException(parsed.error.flatten());
    const ua = req.get?.('user-agent') ?? undefined;
    return this.auth.reset(parsed.data.token, parsed.data.newPassword, ip, ua);
  }
}
