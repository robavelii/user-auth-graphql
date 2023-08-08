import mongoose from 'mongoose';
import config from 'config';

export async function connectToMongo() {
  try {
    await mongoose.connect(config.get('dbUrl'));
    console.log('Connected to db');
  } catch (error) {
    console.error(error);
    process.exit(1);
  }
}

