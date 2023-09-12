import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { DatabaseModule } from './database/database.module';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { APP_GUARD } from '@nestjs/core';
import { AuthGuard } from './auth/guards/auth.guard';
import { RolesGuard } from './auth/guards/roles.guard';

@Module({
  imports: [DatabaseModule, AuthModule,UsersModule],
  controllers: [AppController],
  providers: [AppService,
  //   {
  //   provide: APP_GUARD,
  //   useClass: RolesGuard,
  // },
  // {
  //   provide: APP_GUARD,
  //   useClass: AuthGuard,
  // },
],
})
export class AppModule {}
