import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';

type JwtUser = { userId: string; email: string };
type JwtRequest = Request & { user?: JwtUser };

@Injectable()
export class AdminGuard implements CanActivate {
  canActivate(ctx: ExecutionContext) {
    const req = ctx.switchToHttp().getRequest<JwtRequest>();
    const user = req.user;
    if (!user) throw new UnauthorizedException();
    const admins = (process.env.ADMIN_EMAILS ?? '')
      .split(',')
      .map((s) => s.trim());
    return admins.includes(user.email);
  }
}
