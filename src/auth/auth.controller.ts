import {
  Controller,
  Get,
  Post,
  Body,
  Req,
  UseGuards,
  Delete,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import {
  CreateUserDto,
  CreateUserResponse,
} from 'src/user/dto/create-user.dto';
import {
  ApiBearerAuth,
  ApiForbiddenResponse,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { LoginDTO, TokensResponse } from './dto/login.dto';
import { Request } from 'express';
import { AuthGuard } from './auth.guard';
import { SessionResponse } from './dto/session.dto';
import { SendEmailDto, VerifyEmailDto } from './dto/verifyEmail.dto';
import { AuthRefreshGuard } from './auth-refresh.guard';

@Controller('auth')
@ApiTags('Auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @ApiResponse({ status: 200, type: CreateUserResponse })
  @ApiForbiddenResponse({ description: 'User already exists' })
  @Post('/register')
  register(@Body() createUserDto: CreateUserDto) {
    return this.authService.registerUser(createUserDto);
  }

  @Post('/email')
  sendEmail(@Body() sendEmailDto: SendEmailDto) {
    return this.authService.sendVerificationEmail(sendEmailDto.email);
  }

  @Post('/email/verify')
  verifyEmail(@Body() verifyEmailDto: VerifyEmailDto) {
    return this.authService.verifyEmail(verifyEmailDto);
  }

  @ApiResponse({ status: 200, type: TokensResponse })
  @ApiForbiddenResponse({ description: 'User already exists' })
  @Post('/login')
  login(@Body() loginDto: LoginDTO) {
    return this.authService.login(loginDto);
  }

  @ApiResponse({ status: 200, type: SessionResponse })
  @UseGuards(AuthGuard)
  @ApiBearerAuth()
  @Get('/session')
  getSession(@Req() req: Request) {
    return this.authService.session(req);
  }

  @UseGuards(AuthGuard)
  @ApiBearerAuth()
  @Delete('/logout')
  logout(@Req() req: Request) {
    return this.authService.logout(req);
  }

  @ApiResponse({ status: 200, type: TokensResponse })
  @UseGuards(AuthRefreshGuard)
  @ApiBearerAuth()
  @Post('/refresh')
  refreshToken(@Req() req: Request) {
    return this.authService.refreshToken(req);
  }
}
