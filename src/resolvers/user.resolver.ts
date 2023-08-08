import { Arg, Mutation, Query, Resolver, Ctx } from 'type-graphql';
import { User, CreateUserInput, LoginInput } from '../models/user.schema';
import UserService from '../services/user.service';
import Context from '../types/context';

@Resolver()
export default class UserResolver {
  constructor(private userService: UserService) {
    this.userService = new UserService();
  }

  @Mutation(() => User)
  createUser(@Arg('input') input: CreateUserInput) {
    return this.userService.createUser(input);
  }

  @Mutation(() => String) //Returns the JWT
  login(@Arg('input') input: LoginInput, @Ctx() context: Context) {
    return this.userService.login(input, context);
  }

  @Query(() => User)
  me(@Ctx() context: Context) {
    return context.user;
  }
}

