import { Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { PrismaService } from 'src/core/prisma/prisma.service';

export type AuditAction =
  | 'auth.register'
  | 'auth.login.success'
  | 'auth.login.failed'
  | 'auth.logout'
  | 'token.refresh'
  | 'user.totp.enabled'
  | 'user.totp.disabled'
  | 'password.forgot'
  | 'password.reset'
  | 'user.password.changed'
  | 'user.blocked'
  | 'user.unblocked';

@Injectable()
export class AuditService {
  constructor(private prisma: PrismaService) {}
  log(
    action: AuditAction,
    userId?: string,
    ip?: string,
    userAgent?: string,
    metadata?: Prisma.InputJsonValue,
  ) {
    return this.prisma.auditLog.create({
      data: { action, userId, ip, userAgent, metadata },
    });
  }
}
