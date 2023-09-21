import { Module } from '@nestjs/common';
import { UsersService } from './users.service';
import { UsersController } from './users.controller';
import { userProviders } from './user.providers';
import { DatabaseModule } from 'src/database/database.module';
import { RolesGuard } from 'src/auth/guards/roles.guard';
import { APP_GUARD } from '@nestjs/core';
import { AuthGuard } from 'src/auth/guards/auth.guard';

@Module({
  providers: [
    UsersService,
    ...userProviders,

  ],
  exports: [UsersService],
  imports: [DatabaseModule],
  controllers: [UsersController],
})
export class UsersModule {}
