import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, IsNumber, IsString } from 'class-validator';

export class SendEmailDto {
  @ApiProperty({ type: String, name: 'email', example: 'johnsnow@gmail.com' })
  @IsEmail({}, { message: 'Invalid Email!' })
  @IsNotEmpty({ message: 'Email must not be empty' })
  @IsString({ message: 'Email must be a string' })
  readonly email: string;
}

export class VerifyEmailDto extends SendEmailDto {
  @ApiProperty({ type: Number, name: 'code', example: 123456 })
  @IsNumber({}, { message: 'code must be a number' })
  readonly code: number;
}
