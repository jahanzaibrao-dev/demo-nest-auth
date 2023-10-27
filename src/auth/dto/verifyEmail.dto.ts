import { ApiProperty } from '@nestjs/swagger';
import {
  IsDefined,
  IsEmail,
  IsNotEmpty,
  IsNumber,
  IsString,
  Max,
  Min,
} from 'class-validator';

export class SendEmailDto {
  @ApiProperty({ type: String, name: 'email', example: 'johnsnow@gmail.com' })
  @IsEmail({}, { message: 'Invalid Email!' })
  @IsNotEmpty({ message: 'Email must not be empty' })
  @IsString({ message: 'Email must be a string' })
  @IsDefined({ message: 'Email must be defined' })
  readonly email: string;
}

export class VerifyEmailDto extends SendEmailDto {
  @ApiProperty({ type: Number, name: 'code', example: 123456 })
  @IsNumber({}, { message: 'code must be a number' })
  @IsDefined({ message: 'code must be defined' })
  @Min(100000, { message: 'Code must have exactly 6 digits' })
  @Max(999999, { message: 'Code must have exactly 6 digits' })
  readonly code: number;
}
