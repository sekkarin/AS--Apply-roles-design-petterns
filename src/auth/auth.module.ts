import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtModule } from '@nestjs/jwt';
import { UsersModule } from 'src/users/users.module';
import { MulterModule } from '@nestjs/platform-express';
import { storage } from '../utils/storage';

@Module({
  controllers: [AuthController],
  providers: [AuthService],
  imports: [
    UsersModule,
    JwtModule.register({
      global: true,
      secret: 'Hello World',
    }),
    MulterModule.register({
      storage: storage('/profile'),
      fileFilter(req, file, callback) {
        const typeArray = file.mimetype.split('/');
        const fileType = typeArray[1];
        if (fileType == 'jpg' || fileType == 'png' || fileType == 'pdf') {
          callback(null, true);
        } else {
          callback(null, false);
        }
      },
      // limits
    }),
  ],
})
export class AuthModule {}
