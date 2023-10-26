import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from './../src/app.module';
import mongoose, { Model } from 'mongoose';
import * as bcrypt from 'bcryptjs';
import {
  createUserDTOMock,
  mockedRegisterResponse,
} from 'src/auth/mocks/auth.mocks';
import { getModelToken } from '@nestjs/mongoose';
import { User } from 'src/user/schemas/user.schema';
import { MailerModule, MailerService } from '@nestjs-modules/mailer';

describe('AppController (e2e)', () => {
  let app: INestApplication;
  let server;
  let userModel: Model<User>;
  let mailerService: MailerService;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [
        AppModule,
        MailerModule.forRoot({
          transport: {
            host: 'testHost',
            port: 100,
            secure: false,
            auth: {
              user: 'testUser@example.com',
              pass: '123456jdh',
            },
          },
          defaults: {
            from: 'testUser@example.com',
          },
          preview: true,
        }),
      ],
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
    beforeEach(async () => {
      const hashedPass = await bcrypt.hash(createUserDTOMock.password, 5);
      const mockUser = {
        ...createUserDTOMock,
        password: hashedPass,
      };
      await userModel.create(mockUser);
      jest.spyOn(mailerService, 'sendMail');
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
  });
});
