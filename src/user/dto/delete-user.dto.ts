import { BadRequestException } from '@nestjs/common';
import { Transform } from 'class-transformer';
import { IsDefined, IsMongoId, IsString } from 'class-validator';
import { Types } from 'mongoose';

export const SafeMongoIdTransform = ({ value }) => {
  try {
    if (
      Types.ObjectId.isValid(value) &&
      new Types.ObjectId(value).toString() === value
    ) {
      return value;
    }
    throw new BadRequestException('Invalid Mongo Id');
  } catch (error) {
    throw new BadRequestException('Invalid Mongo Id');
  }
};

export class UserIdDTO {
  @IsMongoId()
  @IsString({ message: 'userId must be a string' })
  @IsDefined({ message: 'userId must be present' })
  @Transform((value) => SafeMongoIdTransform(value))
  userId: string;
}
