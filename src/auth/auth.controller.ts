import { Controller, Get, Post, Body, Req, UseGuards } from '@nestjs/common';
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
import { LoginDTO, LoginResponse } from './dto/login.dto';
import { Request } from 'express';
import { AuthGuard } from './auth.guard';
import { SessionResponse } from './dto/session.dto';

@Controller('auth')
@ApiTags('Auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @ApiResponse({ status: 200, type: CreateUserResponse })
  @ApiForbiddenResponse({ description: 'User already exists' })
  @Post('/register')
  register(@Body() createUserDto: CreateUserDto) {
    return this.authService.create(createUserDto);
  }

  @ApiResponse({ status: 200, type: LoginResponse })
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
}
