import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from 'src/core/prisma/prisma.service';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';

@Injectable()
export class TokensService {
  constructor(
    private jwt: JwtService,
    private prisma: PrismaService,
  ) {}

  signAccessToken(payload: Record<string, unknown>): Promise<string> {
    return this.jwt.signAsync(payload);
  }

  async issueRefreshToken(userId: string, ip?: string, userAgent?: string) {
    const raw = crypto.randomBytes(64).toString('base64url');
    const tokenHash = await bcrypt.hash(raw, 12);
    const refreshTtl =
      (process.env.JWT_REFRESH_EXPIRES as
        | `${number}${'s' | 'm' | 'h' | 'd'}`
        | undefined) ?? '30d';
    const expires = new Date(Date.now() + parseMs(refreshTtl));

    await this.prisma.refreshToken.create({
      data: { userId, tokenHash, ip, userAgent, expiresAt: expires },
    });

    return raw;
  }

  async rotateRefreshToken(prevRaw: string, ip?: string, userAgent?: string) {
    const token = await this.findValidRefresh(prevRaw);
    if (!token) throw new UnauthorizedException('Invalid refresh');

    await this.prisma.refreshToken.update({
      where: { id: token.id },
      data: { revokedAt: new Date() },
    });

    return this.issueRefreshToken(token.userId, ip, userAgent);
  }

  async findValidRefresh(raw: string) {
    const tokens = await this.prisma.refreshToken.findMany({
      where: { revokedAt: null, expiresAt: { gt: new Date() } },
      orderBy: { createdAt: 'desc' },
      take: 200,
    });

    for (const t of tokens) {
      if (await bcrypt.compare(raw, t.tokenHash)) return t;
    }
    return null;
  }
}

function parseMs(s: `${number}${'s' | 'm' | 'h' | 'd'}`): number {
  const num = Number(s.slice(0, -1));
  const unit = s.slice(-1);
  const map: Record<string, number> = {
    s: 1000,
    m: 60000,
    h: 3600000,
    d: 86400000,
  };
  return num * map[unit];
}
