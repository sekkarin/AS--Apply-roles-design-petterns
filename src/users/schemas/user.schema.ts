// "email": "ella@prisma.io",
//   "name": "Ella",
//   "role": "ADMIN"
import * as mongoose from 'mongoose';

export const UserSchema = new mongoose.Schema({
  email: String,
  password: String,
  name: String,
  role: {
    User: {
      default: 'USER',
      type: String,
    },
    Admin: String,
  },
  username: String,
  refreshToken: String,
  isAlive: {
    type: Boolean,
    default: false,
  },
});
