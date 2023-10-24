import { Test, TestingModule } from '@nestjs/testing';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { createSpyObj } from 'jest-createspyobj';
import { JwtModule } from '@nestjs/jwt';
import { UserService } from 'src/user/user.service';

describe('AuthController', () => {
  let controller: AuthController;
  const authServiceMock = createSpyObj('AuthService', [
    'registerUser',
    'login',
    'sendVerificationEmail',
    'verifyEmail',
    'session',
    'logout',
    'generateTokens',
  ]);

  const userServiceMock = createSpyObj('UserService', [
    'create',
    'validateUser',
    'getUserByEmail',
  ]);

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      imports: [JwtModule],
      providers: [
        { provide: AuthService, useValue: authServiceMock },
        { provide: UserService, useValue: userServiceMock },
      ],
    }).compile();

    controller = module.get<AuthController>(AuthController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
