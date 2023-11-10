import { Module } from '@nestjs/common';
import { UserModule } from './user/user.module';
import { MongooseModule } from '@nestjs/mongoose';
import { ConfigModule } from '@nestjs/config';
import { AuthModule } from './auth/auth.module';
import { AuthService } from './auth/auth.service';
import { MailerModule } from '@nestjs-modules/mailer';

const getDatabaseURI = () => {
  if (process.env.NODE_ENV == 'test') {
    console.log('in app test db');
    return;
  }
  return process.env.DB_CONNECTION_URI || '';
};

@Module({
  providers: [AuthService],
  imports: [
    ConfigModule.forRoot(),
    MailerModule.forRoot({
      transport: {
        host: process.env.SMTP_HOST,
        port: process.env.SMTP_PORT,
        secure: false,
        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASSWORD,
        },
      },
      defaults: {
        from: '"No Reply" <no-reply@nestauthapp>',
      },
      preview: true,
    }),
    UserModule,
    ...(process.env.NODE_ENV !== 'test'
      ? [MongooseModule.forRoot(getDatabaseURI())]
      : []),
    AuthModule,
  ],
})
export class AppModule {}
