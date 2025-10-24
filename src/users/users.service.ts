import { Injectable } from '@nestjs/common';
import { PrismaService } from '../core/prisma/prisma.service';
import * as bcrypt from 'bcrypt';
import { Prisma } from '@prisma/client';

@Injectable()
export class UsersService {
  constructor(private readonly prisma: PrismaService) {}

  findByEmail(email: string) {
    return this.prisma.user.findUnique({ where: { email } });
  }

  async createWithPassword(email: string, password: string) {
    const saltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS ?? '12', 10);
    const passwordHash = await bcrypt.hash(password, saltRounds);
    return this.prisma.user.create({ data: { email, passwordHash } });
  }

  async setPassword(userId: string, newPassword: string) {
    const saltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS ?? '12', 10);
    const passwordHash = await bcrypt.hash(newPassword, saltRounds);
    return this.prisma.user.update({
      where: { id: userId },
      data: { passwordHash },
    });
  }

  findById(id: string) {
    return this.prisma.user.findUnique({ where: { id } });
  }

  async setTotpTempSecret(userId: string, base32: string) {
    return this.prisma.user.update({
      where: { id: userId },
      data: { totTempSecret: base32 },
    });
  }

  async enableTotp(userId: string, base32: string) {
    return this.prisma.user.update({
      where: { id: userId },
      data: { totpSecret: base32, totTempSecret: null, totpEnabled: true },
    });
  }

  async disableTotp(userId: string) {
    return this.prisma.user.update({
      where: { id: userId },
      data: { totpSecret: null, totTempSecret: null, totpEnabled: false },
    });
  }

  updateById(id: string, data: Prisma.UserUpdateInput) {
    return this.prisma.user.update({ where: { id }, data });
  }

  setBlocked(id: string, blocked: boolean) {
    return this.updateById(id, { isBlocked: blocked });
  }
}
