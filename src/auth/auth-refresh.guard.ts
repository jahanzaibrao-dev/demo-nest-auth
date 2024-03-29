import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Observable } from 'rxjs';
import { UserService } from 'src/user/user.service';

@Injectable()
export class AuthRefreshGuard implements CanActivate {
  constructor(
    private jwtService: JwtService,
    private userService: UserService,
  ) {}

  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    const req = context.switchToHttp().getRequest();

    return this.validateRequest(req);
  }

  async validateRequest(req) {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
      throw new UnauthorizedException();
    }

    const bearer = authHeader.split(' ')[0];
    const token = authHeader.split(' ')[1];

    if (bearer !== 'Bearer' || !token) {
      throw new UnauthorizedException();
    }

    let jwtUser;

    try {
      jwtUser = this.jwtService.verify(token, {
        secret: process.env.REFRESH_TOKEN_SECRET,
      });
    } catch (e) {
      throw new UnauthorizedException({ message: 'Invalid Refresh Token' });
    }

    const user = await this.userService.getUserByEmail(jwtUser?.email);

    if (!user) {
      throw new UnauthorizedException({ message: 'User is not present' });
    }

    if (!user.tokens) {
      throw new UnauthorizedException({ message: 'Tokens are not present' });
    }

    if (user.tokens.refreshToken !== token) {
      throw new UnauthorizedException({
        message: 'Token is either old or expired',
      });
    }

    req.user = jwtUser;
    return true;
  }
}
