import { INestApplication, ValidationPipe } from '@nestjs/common';
import { MongooseModule, getModelToken } from '@nestjs/mongoose';
import { Test, TestingModule } from '@nestjs/testing';
import { Model } from 'mongoose';
import { AppModule } from 'src/app.module';
import { AuthService } from 'src/auth/auth.service';
import { User, UserRole } from 'src/user/schemas/user.schema';
import * as bcrypt from 'bcryptjs';
import {
  createUserDTOMock,
  unverifiedUserWithOtpMock,
} from 'src/auth/mocks/auth.mocks';
import * as request from 'supertest';
import { closeTestDB, setupTestDB } from './test-db-setup';
import { Reflector } from '@nestjs/core';

describe('AuthController (e2e)', () => {
  let reflector: Reflector;
  let app: INestApplication;
  let server;
  let userModel: Model<User>;
  let authService: AuthService;

  beforeAll(async () => {
    const mongoUri = await setupTestDB();

    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule, MongooseModule.forRoot(mongoUri)],
      providers: [Reflector],
    }).compile();

    app = moduleFixture.createNestApplication();
    app.useGlobalPipes(new ValidationPipe());

    await app.init();
    server = app.getHttpServer();
    userModel = moduleFixture.get(getModelToken(User.name));
    authService = moduleFixture.get<AuthService>(AuthService);
    reflector = moduleFixture.get<Reflector>(Reflector);
  });

  afterAll(async () => {
    await closeTestDB();
    await app.close();
  });

  afterEach(async () => {
    await userModel.deleteMany({});
  });

  describe('deleteUser', () => {
    let savedUser;

    beforeEach(async () => {
      const hashedPass = await bcrypt.hash(createUserDTOMock.password, 5);
      const mockUser = {
        ...createUserDTOMock,
        password: hashedPass,
        otp: unverifiedUserWithOtpMock.otp,
        isVerified: true,
        role: UserRole.ADMIN,
      };
      savedUser = await userModel.create(mockUser);
      const tokens = authService.generateTokens({
        email: savedUser.email,
        role: savedUser.role,
      });
      savedUser.tokens = tokens;
      await savedUser.save();
    });

    it('should_delete_a_user_successfully', async () => {
      const accessToken = savedUser.tokens.accessToken;
      const response = await request(server)
        .delete(`/user/${savedUser._id}`)
        .auth(accessToken, { type: 'bearer' })
        .expect(200);

      const user = await userModel.findOne({ email: savedUser.email });
      expect(response.body.message).toEqual('User deleted successfully!');
      expect(user).toBe(null);
    });

    it('should_throw_an_exception_if_user_is_not_an_admin', async () => {
      savedUser.role = UserRole.USER;
      const tokens = authService.generateTokens({
        email: savedUser.email,
        role: savedUser.role,
      });
      savedUser.tokens = tokens;
      await savedUser.save();
      const accessToken = savedUser.tokens.accessToken;

      const response = await request(server)
        .delete(`/user/${savedUser._id}`)
        .auth(accessToken, { type: 'bearer' })
        .expect(403);

      expect(response.body.message).toEqual('Forbidden resource');
    });

    it('should_throw_an_exception_if_user_id_is_not_a_valid_mongo_id', async () => {
      const fakeMongoId = 'fak3mong0id';
      const accessToken = savedUser.tokens.accessToken;
      const response = await request(server)
        .delete(`/user/${fakeMongoId}`)
        .auth(accessToken, { type: 'bearer' })
        .expect(400);

      expect(response.body.message).toEqual('Invalid Mongo Id');
    });

    it('should_throw_an_exception_if_user_id_is_not_of_a_valid_user', async () => {
      const wrongUserId = '65323d5bfdc38e4aaf461078';
      const accessToken = savedUser.tokens.accessToken;
      const response = await request(server)
        .delete(`/user/${wrongUserId}`)
        .auth(accessToken, { type: 'bearer' })
        .expect(400);

      expect(response.body.message).toEqual(`User with this id doesn't exist`);
    });

    it('should_throw_unauthorized_exception_if_token_is_missing', async () => {
      const response = await request(server)
        .delete(`/user/${savedUser._id}`)
        .auth('', { type: 'bearer' })
        .expect(401);

      expect(response.body.message).toEqual('Unauthorized');
    });

    it('should_throw_unauthorized_exception_if_token_is_invalid', async () => {
      const response = await request(server)
        .delete(`/user/${savedUser._id}`)
        .auth('InvalidToken', { type: 'bearer' })
        .expect(401);

      expect(response.body.message).toEqual('User is not authorized');
    });

    it('should_throw_unauthorized_if_email_present_in_accessToken_is_invalid', async () => {
      const accessToken = authService.generateTokens({
        email: 'wrongEmail@gmail.com',
        role: UserRole.USER,
      }).accessToken;

      const response = await request(server)
        .delete(`/user/${savedUser._id}`)
        .auth(accessToken, { type: 'bearer' })
        .expect(401);

      expect(response.body.message).toEqual('User is not present');
    });

    it('should_throw_unauthorized_if_tokens_are_not_present_in_db', async () => {
      const accessToken = savedUser.tokens.accessToken;
      await savedUser.updateOne({ $unset: { tokens: 1 } });
      const response = await request(server)
        .delete(`/user/${savedUser._id}`)
        .auth(accessToken, { type: 'bearer' })
        .expect(401);

      expect(response.body.message).toEqual('Tokens are not present');
    });

    it('should_throw_unauthorized_if_tokens_provided_are_expired_or_old', async () => {
      const oldTokens = JSON.parse(JSON.stringify(savedUser.tokens));
      const tokens = authService.generateTokens({
        email: savedUser.email,
        role: UserRole.USER,
      });
      await userModel.updateOne(
        { email: savedUser.email },
        { $set: { tokens: tokens } },
      );

      const response = await request(server)
        .delete(`/user/${savedUser._id}`)
        .auth(oldTokens.accessToken, { type: 'bearer' })
        .expect(401);

      expect(response.body.message).toEqual('Token is either old or expired');
    });
  });
});
