import { Test, TestingModule } from '@nestjs/testing';
import { UserService } from './user.service';
import { User } from './schemas/user.schema';
import { createSpyObj } from 'jest-createspyobj';
import { Model } from 'mongoose';
import { getModelToken } from '@nestjs/mongoose';

describe('UserService', () => {
  let service: UserService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        UserService,
        {
          provide: getModelToken(User.name),
          useValue: Model,
        },
      ],
    }).compile();

    service = module.get<UserService>(UserService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
