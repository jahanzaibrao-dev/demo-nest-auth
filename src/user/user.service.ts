import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { CreateUserDto, CreateUserResponse } from './dto/create-user.dto';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './schemas/user.schema';
import { Model } from 'mongoose';
import * as bcrypt from 'bcryptjs';
import { LoginDTO } from 'src/auth/dto/login.dto';

@Injectable()
export class UserService {
  constructor(@InjectModel(User.name) private user: Model<User>) {}
  async create(createUserDto: CreateUserDto): Promise<CreateUserResponse> {
    const userExist = await this.user.findOne({ email: createUserDto.email });
    if (userExist) {
      throw new HttpException('User already exists', HttpStatus.FORBIDDEN);
    }
    const hashedPassword = await bcrypt.hash(createUserDto.password, 5);
    const newUser = new this.user({
      ...createUserDto,
      password: hashedPassword,
    });
    await newUser.save();

    return {
      message: 'Signed up successfully',
      user: {
        name: newUser.name,
        email: newUser.email,
      },
    };
  }

  findAll() {
    return `This action returns all user`;
  }

  async validateUser(loginDto: LoginDTO) {
    const user = await this.user.findOne({ email: loginDto.email });
    if (!user) {
      throw new HttpException(
        `The provided username or password is incorrect`,
        HttpStatus.BAD_REQUEST,
      );
    }

    const isValidPass = await bcrypt.compare(loginDto.password, user.password);

    if (!isValidPass) {
      throw new HttpException(
        `The provided username or password is incorrect`,
        HttpStatus.BAD_REQUEST,
      );
    }

    return user;
  }

  async getUserByEmail(email: string) {
    return this.user.findOne({ email });
  }
}
