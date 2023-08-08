import dotenv from 'dotenv';
dotenv.config();
import 'reflect-metadata';
import express from 'express';
import { buildSchema } from 'type-graphql';
import { resolvers } from './resolvers/index';
import authChecker from './utils/authChecker';
import { ApolloServer } from '@apollo/server';
import Context from './types/context';
import { verifyJwt } from './utils/jwt';
import { User } from './models/user.schema';
import cookieParser from 'cookie-parser';
import { connectToMongo } from './utils/mongo';

async function bootstrap() {
  const schema = await buildSchema({
    resolvers,
    authChecker,
  });

  const app = express();

  app.use(cookieParser());

  // apollo server
  const server = new ApolloServer({
    schema,
    context: (ctx: Context) => {
      const context = ctx;
      if (ctx.req.cookies.accessToken) {
        const user = verifyJwt<User>(ctx.req.cookies.accessToken);
        context.user = user;
      }
      return context;
    },
    // plugins: [
    //   process.env.NODE_ENV === 'production'
    //     ? ApolloServerPluginLandingPageProductionDefault()
    //     : ApolloServerPluginLandingPageGraphQLPlayground(),
    // ],
  });

  await server.start();

  app.listen(
    {
      port: process.env.PORT || 4000,
    },
    () => {
      console.log(`🚀 Server ready at http://localhost:${process.env.PORT}`);
    }
  );

  connectToMongo();
}
bootstrap();

