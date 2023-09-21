import { Document , UpdateWriteOpResult} from 'mongoose';

export interface User extends Document {
  readonly email: string;
  readonly password: string;
  readonly name: string;
  readonly role: {
    User:string,
    Admin:string,
  };
  readonly _id: string;
  readonly username: string;
  refreshToken: string;
  readonly isAlive: string;
  readonly profileUrl: string;
}
