import {
  BadRequestException,
  Inject,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { AuditService } from 'src/audit/audit.service';
import { TokensService } from 'src/tokens/tokens.service';
import { UsersService } from 'src/users/users.service';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import { Cache } from 'cache-manager';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { PrismaService } from 'src/core/prisma/prisma.service';
import { MailerService } from 'src/core/mailer/mailer.service';
import { Prisma } from '@prisma/client';

type CacheWithOptionsTtl = {
  set(
    key: string,
    value: unknown,
    options?: { ttl?: number },
  ): Promise<void> | void;
  get<T = unknown>(key: string): Promise<T | undefined> | T | undefined;
  del(key: string): Promise<void> | void;
};

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  private readonly cacheV5: CacheWithOptionsTtl;

  constructor(
    private users: UsersService,
    private tokens: TokensService,
    private audit: AuditService,
    private readonly prisma: PrismaService,
    private readonly mailer: MailerService,
    @Inject(CACHE_MANAGER) private cache: Cache,
  ) {
    this.cacheV5 = this.cache as unknown as CacheWithOptionsTtl;
  }

  async register(email: string, password: string, ip?: string, ua?: string) {
    const exists = await this.users.findByEmail(email);
    if (exists) throw new BadRequestException('Email already in use');
    const user = await this.users.createWithPassword(email, password);
    await this.audit.log('auth.register', user.id, ip, ua);
    return user;
  }

  async login(email: string, password: string, ip?: string, ua?: string) {
    const user = await this.users.findByEmail(email);
    if (!user || !user.passwordHash) {
      await this.audit.log('auth.login.failed', undefined, ip, ua, { email });
      throw new UnauthorizedException('Invalid credentials');
    }
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok || user.isBlocked) {
      await this.audit.log('auth.login.failed', user.id, ip, ua);
      throw new UnauthorizedException('Invalid credentials');
    }

    if (user.totpEnabled && user.totpSecret) {
      const ticket = `t_${user.id}_${Date.now()}`;
      const key = `login:ticket:${ticket}`;
      await this.cacheV5.set(key, user.id, { ttl: 300_000 });
      return { requiresTOTP: true, ticket };
    }

    const access = await this.tokens.signAccessToken({
      sub: user.id,
      email: user.email,
    });
    const refresh = await this.tokens.issueRefreshToken(user.id, ip, ua);
    await this.audit.log('auth.login.success', user.id, ip, ua);
    return { accessToken: access, refreshToken: refresh };
  }

  async refresh(refreshRaw: string, ip?: string, ua?: string) {
    const token = await this.tokens.findValidRefresh(refreshRaw);
    if (!token) {
      await this.audit.log('token.refresh', undefined, ip, ua, {
        status: 'invalid',
      });
      throw new UnauthorizedException('Invalid refresh');
    }
    const access = await this.tokens.signAccessToken({ sub: token.userId });
    const newRefresh = await this.tokens.rotateRefreshToken(refreshRaw, ip, ua);
    await this.audit.log('token.refresh', token.userId, ip, ua, {
      rotatedFrom: token.id,
    });
    return { accessToken: access, refreshToken: newRefresh };
  }

  async logout(refreshRaw: string, ip?: string, ua?: string) {
    const token = await this.tokens.findValidRefresh(refreshRaw);
    if (token) {
      await this.tokens['prisma'].refreshToken.update({
        where: { id: token.id },
        data: { revokedAt: new Date() },
      });
      await this.audit.log('auth.logout', token.userId, ip, ua);
    }
  }

  async verifyTotpLogin(
    ticket: string,
    code: string,
    ip?: string,
    ua?: string,
  ) {
    const key = `login:ticket:${ticket}`;

    const userId = await this.cache.get<string>(key);

    if (!userId) {
      this.logger.warn(`[TOTP VERIFY] ticket missing or expired: ${key}`);
      throw new UnauthorizedException('Invalid or expired ticket');
    }

    const user = await this.users.findById(userId);
    if (!user || !user.totpEnabled || !user.totpSecret) {
      this.logger.warn(`[TOTP VERIFY] user not eligible: ${userId}`);
      throw new UnauthorizedException('TOTP not enabled');
    }

    const speakeasy = await import('speakeasy');
    const ok = speakeasy.totp.verify({
      secret: user.totpSecret,
      encoding: 'base32',
      token: code,
      window: 1,
    });

    if (!ok) throw new UnauthorizedException('Invalid TOTP code');
    await this.cache.del(key);
    const access = await this.tokens.signAccessToken({
      sub: user.id,
      email: user.email,
    });
    const refresh = await this.tokens.issueRefreshToken(user.id, ip, ua);
    await this.audit.log('auth.login.success', user.id, ip, ua, {
      totp: 'verified',
    });

    return { accessToken: access, refreshToken: refresh };
  }

  async forgot(email: string, ip?: string, ua?: string) {
    const user = await this.users.findByEmail(email);
    if (!user) return { ok: true };

    const raw = crypto.randomBytes(32).toString('base64url');
    const tokenHash = await bcrypt.hash(raw, 12);
    const expires = new Date(Date.now() + 15 * 60_000);

    await this.prisma.passwordReset.create({
      data: { userId: user.id, tokenHash, expiresAt: expires },
    });

    const link = `${process.env.APP_URL}/reset?token=${raw}`;
    await this.mailer.send(
      user.email,
      'Reset your password',
      `<p>Para restablecer tu contraseña, haz clic: <a href="${link}">${link}</a></p>
     <p>Vence en 15 minutos.</p>`,
    );

    await this.audit.log('password.forgot', user.id, ip, ua);
    return { ok: true };
  }

  async reset(token: string, newPassword: string, ip?: string, ua?: string) {
    const findArgs: Prisma.PasswordResetFindManyArgs = {
      where: { usedAt: null, expiresAt: { gt: new Date() } },
      orderBy: { expiresAt: 'desc' },
      take: 200,
    };

    const candidates = await this.prisma.passwordReset.findMany(findArgs);

    for (const pr of candidates) {
      const { tokenHash, userId, id } = pr;

      const matches = await bcrypt.compare(token, tokenHash);
      if (!matches) continue;

      await this.users.setPassword(userId, newPassword);

      const upd: Prisma.PasswordResetUpdateArgs = {
        where: { id },
        data: { usedAt: new Date() },
      };
      await this.prisma.passwordReset.update(upd);

      await this.audit.log('password.reset', userId, ip, ua);
      return { changed: true };
    }

    throw new BadRequestException('Invalid or expired token');
  }
}
