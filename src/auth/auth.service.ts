import {
  HttpException,
  HttpStatus,
  Inject,
  Injectable,
  forwardRef,
} from '@nestjs/common';

import { CreateUserDto } from 'src/user/dto/create-user.dto';
import { UserService } from 'src/user/user.service';
import { LoginDTO, LoginResponse } from './dto/login.dto';
import { JwtService } from '@nestjs/jwt';
import { SessionResponse } from './dto/session.dto';
import { MailerService } from '@nestjs-modules/mailer';
import { VerifyEmailDto } from './dto/verifyEmail.dto';

@Injectable()
export class AuthService {
  constructor(
    @Inject(forwardRef(() => UserService)) private userService: UserService,
    private jwtService: JwtService,
    private mailerService: MailerService,
  ) {}

  registerUser(createUserDto: CreateUserDto) {
    return this.userService.create(createUserDto);
  }

  async login(loginDTO: LoginDTO): Promise<LoginResponse> {
    const user = await this.userService.validateUser(loginDTO);

    if (!user.isVerified) {
      throw new HttpException(`User is not verified`, HttpStatus.FORBIDDEN);
    }
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

  async sendVerificationEmail(email: string) {
    const user = await this.userService.getUserByEmail(email);
    if (!user) {
      throw new HttpException(
        `User with this email doesn't exist`,
        HttpStatus.BAD_REQUEST,
      );
    }

    if (user.isVerified) {
      throw new HttpException(`User already verified`, HttpStatus.FORBIDDEN);
    }
    try {
      const code = Math.floor(100000 + Math.random() * 900000);
      user.otp = code;
      await user.save();
      await this.mailerService.sendMail({
        to: email,
        subject: 'Verification code of nest auth app',
        html: ` <div>
      <p>Your 6 digit verification code is: <strong>${code}</strong></p>
  </div>`,
      });

      return {
        message: 'Verification code sent successfully!',
      };
    } catch (err) {
      throw new HttpException(
        `Something went wrong!`,
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  async verifyEmail(verifyEmailDto: VerifyEmailDto) {
    const user = await this.userService.getUserByEmail(verifyEmailDto.email);
    if (!user) {
      throw new HttpException(
        `User with this email doesn't exist`,
        HttpStatus.BAD_REQUEST,
      );
    }

    if (user.isVerified) {
      throw new HttpException(`User already verified`, HttpStatus.FORBIDDEN);
    }

    if (verifyEmailDto.code !== user.otp) {
      throw new HttpException(`Invalid code`, HttpStatus.FORBIDDEN);
    }

    user.isVerified = true;
    await user.save();

    return {
      message: 'User verified successfully',
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

  async logout(req) {
    const user = await this.userService.getUserByEmail(req.user?.email);
    if (!user) {
      throw new HttpException(
        `User with this email doesn't exist`,
        HttpStatus.BAD_REQUEST,
      );
    }

    await user.updateOne({ $unset: { tokens: 1 } });

    return {
      message: 'User Logged out successfully!',
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
