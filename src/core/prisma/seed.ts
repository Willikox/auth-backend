import { PrismaClient } from '@prisma/client';
import * as bcrypt from 'bcrypt';

const prisma = new PrismaClient();

async function main() {
  const email = 'admin@will.com';
  const password = 'AdminPwd123!';
  const hash = await bcrypt.hash(password, 12);

  await prisma.user.upsert({
    where: { email },
    update: { role: 'ADMIN', passwordHash: hash, isBlocked: false },
    create: { email, role: 'ADMIN', passwordHash: hash },
  });
}

void main().finally(() => prisma.$disconnect());
