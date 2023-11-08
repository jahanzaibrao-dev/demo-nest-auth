import { MongoMemoryServer } from 'mongodb-memory-server';
import mongoose from 'mongoose';

let mongod: MongoMemoryServer;

export async function setupTestDB() {
  mongod = await MongoMemoryServer.create();
  const uri = await mongod.getUri();

  await mongoose.connect(uri);

  mongoose.connection.on('connected', () => {
    console.log('Connected to the test database');
  });

  return uri;
}

export async function closeTestDB() {
  await mongoose.connection.close();
  await mongod.stop();
}
