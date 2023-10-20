import { Schema, Prop, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument } from 'mongoose';

export type UserDocument = HydratedDocument<User>;

export enum UserRole {
  USER = 'USER',
  ADMIN = 'ADMIN',
}

export class JWTTokens {
  accessToken: string;
  refreshToken: string;
}

@Schema()
export class User {
  @Prop()
  name: string;

  @Prop({ required: true, unique: true })
  email: string;

  @Prop({ required: true })
  password: string;

  @Prop()
  age: number;

  @Prop({ default: UserRole.USER })
  role: UserRole;

  @Prop()
  tokens: JWTTokens;

  @Prop({ default: false })
  isVerified: boolean;

  @Prop()
  otp: number;
}

export const UserSchema = SchemaFactory.createForClass(User);
