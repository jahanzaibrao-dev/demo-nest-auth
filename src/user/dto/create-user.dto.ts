import { ApiProperty } from '@nestjs/swagger';
import {
  IsDefined,
  IsEmail,
  IsNotEmpty,
  IsNumber,
  IsOptional,
  IsString,
  Min,
} from 'class-validator';

export class CreateUserResponse {
  @ApiProperty({ example: 'Signed up successfully' })
  message: string;
  @ApiProperty({
    example: {
      name: 'John Snow',
      email: 'johnSnow@gmail.com',
    },
  })
  user: {
    name: string;
    email: string;
  };
}

export class CreateUserDto {
  @ApiProperty({ type: String, name: 'name', example: 'John Snow' })
  @IsString({ message: 'Name must be a string' })
  @IsNotEmpty({ message: 'Name must not be empty' })
  @IsOptional()
  readonly name?: string;

  @ApiProperty({ type: String, name: 'email', example: 'johnSnow@gmail.com' })
  @IsEmail({}, { message: 'Invalid Email!' })
  @IsNotEmpty({ message: 'Email must not be empty' })
  @IsString({ message: 'Email must be a string' })
  @IsDefined({ message: 'Email must be defined' })
  readonly email: string;

  @ApiProperty({ type: String, name: 'password', example: 'securePhrase' })
  @IsNotEmpty({ message: 'Password must not be empty' })
  @IsString({ message: 'Password must be a string' })
  @IsDefined({ message: 'Password must be defined' })
  readonly password: string;

  @ApiProperty({ type: Number, name: 'age', example: 17 })
  @IsNumber({}, { message: 'Age must be a number' })
  @Min(17, { message: 'Age must be greater than 16' })
  @IsOptional()
  readonly age?: number;
}
