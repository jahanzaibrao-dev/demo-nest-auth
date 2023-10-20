import { Inject, Injectable, forwardRef } from '@nestjs/common';

import { CreateUserDto } from 'src/user/dto/create-user.dto';
import { UserService } from 'src/user/user.service';
import { LoginDTO, LoginResponse } from './dto/login.dto';
import { JwtService } from '@nestjs/jwt';
import { SessionResponse } from './dto/session.dto';

@Injectable()
export class AuthService {
  constructor(
    @Inject(forwardRef(() => UserService)) private userService: UserService,
    private jwtService: JwtService,
  ) {}

  create(createUserDto: CreateUserDto) {
    return this.userService.create(createUserDto);
  }

  async login(loginDTO: LoginDTO): Promise<LoginResponse> {
    const user = await this.userService.validateUser(loginDTO);
    const payload = {
      email: user.email,
      role: user.role,
    };

    const { accessToken, refreshToken } = this.generateTokens(payload);
    user.tokens = { accessToken, refreshToken };
    await user.save();

    return {
      message: 'Logged In successfully',
      tokens: user.tokens,
    };
  }

  async session(req): Promise<SessionResponse> {
    const user = await this.userService.getUserByEmail(req.user.email);

    return {
      email: user.email,
      name: user.name,
      role: user.role,
      age: user.age,
    };
  }

  generateTokens(payload) {
    const accessToken = this.jwtService.sign(
      {
        email: payload.email,
        role: payload.role,
      },
      {
        secret: process.env.ACCESS_TOKEN_SECRET,
        expiresIn: '1h',
      },
    );
    const refreshToken = this.jwtService.sign(
      { email: payload.email, role: payload.role },
      {
        secret: process.env.REFRESH_TOKEN_SECRET,
        expiresIn: '24h',
      },
    );
    return { accessToken, refreshToken };
  }
}
