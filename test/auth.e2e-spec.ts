import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from './../src/app.module';
import mongoose, { Model } from 'mongoose';
import * as bcrypt from 'bcryptjs';
import {
  createUserDTOMock,
  loginDtoMock,
  mockedRegisterResponse,
  unverifiedUserWithOtpMock,
} from 'src/auth/mocks/auth.mocks';
import { getModelToken } from '@nestjs/mongoose';
import { User } from 'src/user/schemas/user.schema';
import { MailerService } from '@nestjs-modules/mailer';
import { VerifyEmailDto } from 'src/auth/dto/verifyEmail.dto';

describe('AppController (e2e)', () => {
  let app: INestApplication;
  let server;
  let userModel: Model<User>;
  let mailerService: MailerService;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    app.useGlobalPipes(new ValidationPipe());

    await app.init();
    server = app.getHttpServer();
    userModel = moduleFixture.get(getModelToken(User.name));
    mailerService = moduleFixture.get<MailerService>(MailerService);
  });

  afterAll(async () => {
    await mongoose.connection.close();
    await app.close();
  });

  afterEach(async () => {
    await userModel.deleteMany({});
  });

  describe('register', () => {
    it('should_invoke_register_api_and_register_a_new_user_successfully', async () => {
      const response = await request(server)
        .post('/auth/register')
        .send(createUserDTOMock)
        .expect(201);

      expect(response.body).toEqual(mockedRegisterResponse);
      const user = await userModel.findOne({ email: createUserDTOMock.email });
      expect(user).toBeTruthy();
      expect(user.email).toEqual(createUserDTOMock.email);
    });

    it('should_throw_an_exception_if_a_with_same_email_already_exists', async () => {
      const existingUser = await userModel.create(createUserDTOMock);
      await existingUser.save();
      const response = await request(server)
        .post('/auth/register')
        .send(createUserDTOMock)
        .expect(403);

      expect(response.body.message).toEqual('User already exists');
    });

    it('should_throw_an_exception_if_email_is_not_defined', async () => {
      const mockUser = {
        ...createUserDTOMock,
        email: undefined,
      };
      const response = await request(server)
        .post('/auth/register')
        .send(mockUser)
        .expect(400);

      expect(response.body.message).toContain('Email must be defined');
    });

    it('should_throw_an_exception_if_email_is_empty', async () => {
      const mockUser = {
        ...createUserDTOMock,
        email: '',
      };
      const response = await request(server)
        .post('/auth/register')
        .send(mockUser)
        .expect(400);

      expect(response.body.message).toContain('Email must not be empty');
    });

    it('should_throw_an_exception_if_email_format_is_invalid', async () => {
      const mockUser = {
        ...createUserDTOMock,
        email: 'invalidEmail',
      };
      const response = await request(server)
        .post('/auth/register')
        .send(mockUser)
        .expect(400);

      expect(response.body.message).toContain('Invalid Email!');
    });

    it('should_throw_an_exception_if_email_is_not_a_string', async () => {
      const mockUser = {
        ...createUserDTOMock,
        email: 1234,
      };
      const response = await request(server)
        .post('/auth/register')
        .send(mockUser)
        .expect(400);

      expect(response.body.message).toContain('Email must be a string');
    });

    it('should_throw_an_exception_if_password_is_not_defined', async () => {
      const mockUser = {
        ...createUserDTOMock,
        password: undefined,
      };
      const response = await request(server)
        .post('/auth/register')
        .send(mockUser)
        .expect(400);

      expect(response.body.message).toContain('Password must be defined');
    });

    it('should_throw_an_exception_if_password_is_empty', async () => {
      const mockUser = {
        ...createUserDTOMock,
        password: '',
      };
      const response = await request(server)
        .post('/auth/register')
        .send(mockUser)
        .expect(400);

      expect(response.body.message).toContain('Password must not be empty');
    });

    it('should_throw_an_exception_if_password_is_not_a_string', async () => {
      const mockUser = {
        ...createUserDTOMock,
        password: 1234,
      };
      const response = await request(server)
        .post('/auth/register')
        .send(mockUser)
        .expect(400);

      expect(response.body.message).toContain('Password must be a string');
    });

    it('should_throw_an_exception_if_name_is_not_a_string', async () => {
      const mockUser = {
        ...createUserDTOMock,
        name: 1234,
      };
      const response = await request(server)
        .post('/auth/register')
        .send(mockUser)
        .expect(400);

      expect(response.body.message).toContain('Name must be a string');
    });

    it('should_throw_an_exception_if_name_is_empty', async () => {
      const mockUser = {
        ...createUserDTOMock,
        name: '',
      };
      const response = await request(server)
        .post('/auth/register')
        .send(mockUser)
        .expect(400);

      expect(response.body.message).toContain('Name must not be empty');
    });

    it('should_throw_an_exception_if_age_is_not_a_number', async () => {
      const mockUser = {
        ...createUserDTOMock,
        age: '17',
      };
      const response = await request(server)
        .post('/auth/register')
        .send(mockUser)
        .expect(400);

      expect(response.body.message).toContain('Age must be a number');
    });

    it('should_throw_an_exception_if_age_is_less_than_17', async () => {
      const mockUser = {
        ...createUserDTOMock,
        age: 16,
      };
      const response = await request(server)
        .post('/auth/register')
        .send(mockUser)
        .expect(400);

      expect(response.body.message).toContain('Age must be greater than 16');
    });
  });

  describe('sendEmail', () => {
    let savedUser;
    let spySendMail: jest.SpyInstance;

    beforeEach(async () => {
      const hashedPass = await bcrypt.hash(createUserDTOMock.password, 5);
      const mockUser = {
        ...createUserDTOMock,
        password: hashedPass,
      };
      savedUser = await userModel.create(mockUser);
      spySendMail = jest.spyOn(mailerService, 'sendMail');
    });

    it('should_send_an_otp_to_user_email_successfully', async () => {
      const expectedResponse = {
        message: 'Verification code sent successfully!',
      };

      const response = await request(server)
        .post('/auth/email')
        .send({ email: createUserDTOMock.email })
        .expect(201);

      expect(response.body).toEqual(expectedResponse);
    });

    it('should_throw_an_exception_if_user_does_not_exist', async () => {
      const mockPayload = {
        email: 'wrongEmail@gmail.com',
      };
      const response = await request(server)
        .post('/auth/email')
        .send(mockPayload)
        .expect(400);

      expect(response.body.message).toEqual(
        `User with this email doesn't exist`,
      );
    });

    it('should_throw_an_exception_if_user_is_already_verified', async () => {
      savedUser.isVerified = true;
      await savedUser.save();
      const mockPayload = {
        email: savedUser.email,
      };
      const response = await request(server)
        .post('/auth/email')
        .send(mockPayload)
        .expect(403);

      expect(response.body.message).toEqual(`User already verified`);
    });

    it('should_throw_an_exception_if_mailer_failed_to_send_email', async () => {
      spySendMail.mockRejectedValueOnce('Failed to send email');
      const response = await request(server)
        .post('/auth/email')
        .send({ email: createUserDTOMock.email })
        .expect(500);

      expect(response.body.message).toEqual(`Something went wrong!`);
    });

    it('should_throw_an_exception_if_email_is_not_defined', async () => {
      const mockPayload = {
        email: undefined,
      };
      const response = await request(server)
        .post('/auth/email')
        .send(mockPayload)
        .expect(400);

      expect(response.body.message).toContain('Email must be defined');
    });

    it('should_throw_an_exception_if_email_is_empty', async () => {
      const mockPayload = {
        email: '',
      };
      const response = await request(server)
        .post('/auth/email')
        .send(mockPayload)
        .expect(400);

      expect(response.body.message).toContain('Email must not be empty');
    });

    it('should_throw_an_exception_if_email_format_is_invalid', async () => {
      const mockPayload = {
        email: 'invalidEmail',
      };
      const response = await request(server)
        .post('/auth/email')
        .send(mockPayload)
        .expect(400);

      expect(response.body.message).toContain('Invalid Email!');
    });

    it('should_throw_an_exception_if_email_is_not_a_string', async () => {
      const mockPayload = {
        email: 1234,
      };
      const response = await request(server)
        .post('/auth/email')
        .send(mockPayload)
        .expect(400);

      expect(response.body.message).toContain('Email must be a string');
    });
  });

  describe('verifyEmail', () => {
    let savedUser;

    beforeEach(async () => {
      const hashedPass = await bcrypt.hash(createUserDTOMock.password, 5);
      const mockUser = {
        ...createUserDTOMock,
        password: hashedPass,
        otp: unverifiedUserWithOtpMock.otp,
      };
      savedUser = await userModel.create(mockUser);
    });

    it('should verify a user successfully using otp', async () => {
      const payload: VerifyEmailDto = {
        email: createUserDTOMock.email,
        code: savedUser.otp,
      };

      const response = await request(server)
        .post('/auth/email/verify')
        .send(payload)
        .expect(201);

      const updatedUser = await userModel.findOne({ email: payload.email });

      expect(response.body.message).toEqual('User verified successfully');
      expect(updatedUser.isVerified).toBe(true);
    });

    it('should_throw_an_exception_if_user_does_not_exist', async () => {
      const mockPayload = {
        email: 'wrongEmail@gmail.com',
        code: unverifiedUserWithOtpMock.otp,
      };
      const response = await request(server)
        .post('/auth/email/verify')
        .send(mockPayload)
        .expect(400);

      expect(response.body.message).toEqual(
        `User with this email doesn't exist`,
      );
    });

    it('should_throw_an_exception_if_user_is_already_verified', async () => {
      savedUser.isVerified = true;
      await savedUser.save();
      const mockPayload = {
        email: savedUser.email,
        code: unverifiedUserWithOtpMock.otp,
      };
      const response = await request(server)
        .post('/auth/email/verify')
        .send(mockPayload)
        .expect(403);

      expect(response.body.message).toEqual(`User already verified`);
    });

    it('should_throw_an_exception_if_code_is_incorrect', async () => {
      await savedUser.save();
      const mockPayload = {
        email: savedUser.email,
        code: 102398,
      };
      const response = await request(server)
        .post('/auth/email/verify')
        .send(mockPayload)
        .expect(403);

      expect(response.body.message).toEqual(`Invalid code`);
    });

    it('should_throw_an_exception_if_email_is_not_defined', async () => {
      const mockPayload = {
        email: undefined,
        code: unverifiedUserWithOtpMock.otp,
      };
      const response = await request(server)
        .post('/auth/email/verify')
        .send(mockPayload)
        .expect(400);

      expect(response.body.message).toContain('Email must be defined');
    });

    it('should_throw_an_exception_if_email_is_empty', async () => {
      const mockPayload = {
        email: '',
        code: unverifiedUserWithOtpMock.otp,
      };
      const response = await request(server)
        .post('/auth/email/verify')
        .send(mockPayload)
        .expect(400);

      expect(response.body.message).toContain('Email must not be empty');
    });

    it('should_throw_an_exception_if_email_format_is_invalid', async () => {
      const mockPayload = {
        email: 'invalidEmail',
        code: unverifiedUserWithOtpMock.otp,
      };
      const response = await request(server)
        .post('/auth/email/verify')
        .send(mockPayload)
        .expect(400);

      expect(response.body.message).toContain('Invalid Email!');
    });

    it('should_throw_an_exception_if_email_is_not_a_string', async () => {
      const mockPayload = {
        email: 1234,
        code: unverifiedUserWithOtpMock.otp,
      };
      const response = await request(server)
        .post('/auth/email/verify')
        .send(mockPayload)
        .expect(400);

      expect(response.body.message).toContain('Email must be a string');
    });

    it('should_throw_an_exception_if_code_is_not_defined', async () => {
      const mockPayload = {
        email: unverifiedUserWithOtpMock.email,
        code: undefined,
      };
      const response = await request(server)
        .post('/auth/email/verify')
        .send(mockPayload)
        .expect(400);

      expect(response.body.message).toContain('code must be defined');
    });

    it('should_throw_an_exception_if_code_is_not_a_number', async () => {
      const mockPayload = {
        email: unverifiedUserWithOtpMock.email,
        code: '1233',
      };
      const response = await request(server)
        .post('/auth/email/verify')
        .send(mockPayload)
        .expect(400);

      expect(response.body.message).toContain('code must be a number');
    });

    it('should_throw_an_exception_if_code_is_less_than_6_digits', async () => {
      const mockPayload = {
        email: unverifiedUserWithOtpMock.email,
        code: 12345,
      };
      const response = await request(server)
        .post('/auth/email/verify')
        .send(mockPayload)
        .expect(400);

      expect(response.body.message).toContain(
        'Code must have exactly 6 digits',
      );
    });

    it('should_throw_an_exception_if_code_is_greater_than_6_digits', async () => {
      const mockPayload = {
        email: unverifiedUserWithOtpMock.email,
        code: 1234567,
      };
      const response = await request(server)
        .post('/auth/email/verify')
        .send(mockPayload)
        .expect(400);

      expect(response.body.message).toContain(
        'Code must have exactly 6 digits',
      );
    });
  });

  describe('login', () => {
    let savedUser;

    beforeEach(async () => {
      const hashedPass = await bcrypt.hash(createUserDTOMock.password, 5);
      const mockUser = {
        ...createUserDTOMock,
        password: hashedPass,
        otp: unverifiedUserWithOtpMock.otp,
        isVerified: true,
      };
      savedUser = await userModel.create(mockUser);
    });

    it('should_login_a_user_successfully_and_return_tokens', async () => {
      const response = await request(server)
        .post('/auth/login')
        .send(loginDtoMock)
        .expect(201);

      expect(response.body.message).toEqual('Logged In successfully');
      expect(response.body.tokens.accessToken).toEqual(expect.any(String));
      expect(response.body.tokens.refreshToken).toEqual(expect.any(String));
    });

    it('should_throw_an_exception_if_email_is_not_correct', async () => {
      const payload = { ...createUserDTOMock, email: 'wrongEmail@gmail.com' };

      const response = await request(server)
        .post('/auth/login')
        .send(payload)
        .expect(400);

      expect(response.body.message).toEqual(
        'The provided username or password is incorrect',
      );
    });

    it('should_throw_an_exception_if_password_is_not_correct', async () => {
      const payload = { ...createUserDTOMock, password: 'wrongPass' };

      const response = await request(server)
        .post('/auth/login')
        .send(payload)
        .expect(400);

      expect(response.body.message).toEqual(
        'The provided username or password is incorrect',
      );
    });

    it('should_throw_an_exception_if_user_is_not_verified', async () => {
      savedUser.isVerified = false;
      await savedUser.save();
      const response = await request(server)
        .post('/auth/login')
        .send(loginDtoMock)
        .expect(403);

      expect(response.body.message).toEqual('User is not verified');
    });

    it('should_throw_an_exception_if_email_is_not_defined', async () => {
      const mockPayload = {
        email: undefined,
        password: loginDtoMock.password,
      };
      const response = await request(server)
        .post('/auth/login')
        .send(mockPayload)
        .expect(400);

      expect(response.body.message).toContain('Email must be defined');
    });

    it('should_throw_an_exception_if_email_is_empty', async () => {
      const mockUser = {
        ...loginDtoMock,
        email: '',
      };
      const response = await request(server)
        .post('/auth/login')
        .send(mockUser)
        .expect(400);

      expect(response.body.message).toContain('Email must not be empty');
    });

    it('should_throw_an_exception_if_email_format_is_invalid', async () => {
      const mockUser = {
        ...loginDtoMock,
        email: 'invalidEmail',
      };
      const response = await request(server)
        .post('/auth/login')
        .send(mockUser)
        .expect(400);

      expect(response.body.message).toContain('Invalid Email!');
    });

    it('should_throw_an_exception_if_email_is_not_a_string', async () => {
      const mockUser = {
        ...loginDtoMock,
        email: 1234,
      };
      const response = await request(server)
        .post('/auth/login')
        .send(mockUser)
        .expect(400);

      expect(response.body.message).toContain('Email must be a string');
    });

    it('should_throw_an_exception_if_password_is_not_defined', async () => {
      const mockUser = {
        ...loginDtoMock,
        password: undefined,
      };
      const response = await request(server)
        .post('/auth/login')
        .send(mockUser)
        .expect(400);

      expect(response.body.message).toContain('Password must be defined');
    });

    it('should_throw_an_exception_if_password_is_empty', async () => {
      const mockUser = {
        ...loginDtoMock,
        password: '',
      };
      const response = await request(server)
        .post('/auth/login')
        .send(mockUser)
        .expect(400);

      expect(response.body.message).toContain('Password must not be empty');
    });

    it('should_throw_an_exception_if_password_is_not_a_string', async () => {
      const mockUser = {
        ...loginDtoMock,
        password: 1234,
      };
      const response = await request(server)
        .post('/auth/login')
        .send(mockUser)
        .expect(400);

      expect(response.body.message).toContain('Password must be a string');
    });
  });
});
