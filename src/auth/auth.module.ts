import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { UsersModule } from 'src/users/users.module';
import { TokensModule } from 'src/tokens/tokens.module';
import { AuditModule } from 'src/audit/audit.module';
import { TotpSelfController } from './totp.controller';
import { JwtStrategy } from './jwt.strategy';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { PrismaModule } from 'src/core/prisma/prisma.module';
import { MailerModule } from 'src/core/mailer/mailer.module';

@Module({
  imports: [
    UsersModule,
    TokensModule,
    AuditModule,
    PrismaModule,
    MailerModule,
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.register({
      secret: process.env.JWT_SECRET ?? 'default_jwt_secret',
      signOptions: {
        expiresIn: '1h',
        algorithm: (process.env.JWT_ALG as 'HS256' | 'RS256') || 'HS256',
      },
    }),
  ],
  providers: [AuthService, JwtStrategy],
  controllers: [AuthController, TotpSelfController],
})
export class AuthModule {}
