import {
  getModelForClass,
  prop,
  pre,
  ReturnModelType,
  index,
  queryMethod,
} from '@typegoose/typegoose';
import { AsQueryMethod } from '@typegoose/typegoose/lib/types';
import bcrypt from 'bcrypt';
import { Field, ObjectType, InputType } from 'type-graphql';
import { IsEmail, MinLength, MaxLength } from 'class-validator';

function findByEmail(
  this: ReturnModelType<typeof User, QueryHelpers>,
  email: User['email']
) {
  return this.findOne({
    email,
  });
}
interface QueryHelpers {
  findByEmail: AsQueryMethod<typeof findByEmail>;
}

@pre<User>('save', async function () {
  // check the password is being modified
  if (!this.isModified('password')) {
    return;
  }

  const salt = await bcrypt.genSalt(10);
  const hash = await bcrypt.hashSync(this.password, salt);

  this.password = hash;
})
@index({ email: 1 })
@queryMethod(findByEmail)
@ObjectType()
export class User {
  @Field(() => String)
  _id: string;

  @Field(() => String)
  @prop({ required: true })
  name: string;

  @Field(() => String)
  @prop({ required: true })
  email: string;

  @prop({ required: true })
  password: string;

  @Field(() => Boolean)
  @prop({ default: false })
  otp_enabled: boolean;

  @Field(() => Boolean)
  @prop({ default: false })
  otp_verified: boolean;

  @Field(() => String, { nullable: true })
  @prop()
  otp_ascii?: string;

  @Field(() => String, { nullable: true })
  @prop()
  otp_hex?: string;

  @Field(() => String, { nullable: true })
  @prop()
  otp_base32?: string;

  @Field(() => String, { nullable: true })
  @prop()
  otp_auth_url?: string;
}

export const UserModel = getModelForClass<typeof User, QueryHelpers>(User);

@InputType()
export class CreateUserInput {
  @Field(() => String)
  name: string;

  @IsEmail()
  @Field(() => String)
  email: string;

  @MinLength(6, {
    message: 'Password must be at least 6 characters long',
  })
  @MaxLength(50, {
    message: 'Password must not be longer than 50 characters',
  })
  @Field(() => String)
  password: string;
}

@InputType()
export class LoginInput {
  @Field(() => String)
  email: string;

  @Field(() => String)
  password: string;
}

