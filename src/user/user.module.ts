import { Module } from '@nestjs/common';
import { AuthController } from 'src/auth/auth.controller';
import { UserController } from './user.controller';
import { UserService } from './user.service';

@Module({
    controllers: [UserController],
    providers: [UserService]
})
export class UserModule {}
