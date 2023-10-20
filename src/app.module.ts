import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { UserModule } from './user/user.module';
import { MongooseModule } from '@nestjs/mongoose';
import { ConfigModule } from '@nestjs/config';
import { AuthModule } from './auth/auth.module';
import { AuthService } from './auth/auth.service';

const getDatabaseURI = () => {
  console.log(process.env.DB_CONNECTION_URI);
  return process.env.DB_CONNECTION_URI || '';
};

@Module({
  controllers: [AppController],
  providers: [AppService, AuthService],
  imports: [
    ConfigModule.forRoot(),
    UserModule,
    MongooseModule.forRoot(getDatabaseURI()),
    AuthModule,
  ],
})
export class AppModule {}
