import { Module } from '@nestjs/common';
import { TokensService } from './tokens.service';
import { JwtModule } from '@nestjs/jwt';
import { PrismaModule } from 'src/core/prisma/prisma.module';

@Module({
  imports: [
    PrismaModule,
    JwtModule.register({
      secret: process.env.JWT_SECRET,
      signOptions: {
        algorithm:
          (process.env.JWT_ALG as 'HS256' | 'RS256' | undefined) ?? 'HS256',
        expiresIn:
          (process.env
            .JWT_ACCESS_EXPIRES as `${number}${'s' | 'm' | 'h' | 'd'}`) ??
          '15m',
      },
    }),
  ],
  providers: [TokensService],
  exports: [TokensService],
})
export class TokensModule {}
