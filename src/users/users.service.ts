import {
  Body,
  Inject,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Model } from 'mongoose';
import { User } from './interfaces/user.interface';
import { async } from 'rxjs';
@Injectable()
export class UsersService {
  constructor(
    @Inject('USER_MODEL')
    private userModel: Model<User>,
  ) {}

  async findOne(username: string): Promise<User | undefined> {
    return this.userModel
      .findOne({ username: username })

      .exec();
  }
  async findOneToken(token:string){
    return this.userModel.findOne({refreshToken: token});
  }
  async getUserById(username: string): Promise<User | undefined> {
    return await this.userModel
      .findOne({ username: username })
      .select('-password -refreshToken')
      .exec();
  }
  async getAll(): Promise<User[] | undefined> {
    return this.userModel.find().select('-password -refreshToken').exec();
  }
  async findOneById(id: string): Promise<User | undefined> {
    return this.userModel.findById(id).exec();
  }
  async update(userUpdate: User) {
    return this.userModel.updateOne({ id: userUpdate.id }, userUpdate).exec();
  }

  async createUser(
    @Body() crateUserDto: Record<string, any>,
  ): Promise<User | undefined> {
    const user = await this.findOne(crateUserDto.username);
    if (user) {
      throw new UnauthorizedException();
    }
    const createdUser = new this.userModel(crateUserDto);
    return await createdUser.save();
  }
  async deleteUser(id: string): Promise<User | undefined> {
    return await this.userModel.findOne({ _id: id });
  }
}
