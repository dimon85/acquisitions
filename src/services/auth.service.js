import bcrypt from 'bcrypt';
import { eq } from 'drizzle-orm';
import logger from '#config/logger.js';
import db from '#config/database.js';
import { users } from '#models/user.model.js';

export const hashPassword = async password => {
  try {
    return await bcrypt.hash(password, 10);
  } catch (e) {
    logger.error(`Error hashing the password: ${e}`);
  }
};

export const comparePassword = async (password, hashedPassword) => {
  try {
    return await bcrypt.compare(password, hashedPassword);
  } catch (e) {
    logger.error(`Error comparing the password: ${e}`);
  }
};

export const createUser = async ({ name, email, password, role }) => {
  try {
    const existingUser = await db
      .select()
      .from(users)
      .where(eq(users.email, email))
      .limit(1);

    if (existingUser.length > 0) {
      throw new Error('User already exists');
    }

    const password_hash = await hashPassword(password);

    const [newUser] = await db
      .insert(users)
      .values({ name, email, password: password_hash, role })
      .returning({
        id: users.id,
        name: users.name,
        email: users.email,
        role: users.role,
        created_at: users.created_at,
      });
    logger.info(`User created with email: ${email}`);
    return newUser;
  } catch (e) {
    logger.error(`Error creating the user: ${e}`);
    throw e;
  }
};

export const authenticateUser = async ({ email, password }) => {
  try {
    const existingUser = await db
      .select()
      .from(users)
      .where(eq(users.email, email));
    
    if (existingUser.length === 0) {
      throw new Error('Invalid email or password');
    }

    const isPasswordValid = await comparePassword(password, existingUser[0].password);

    if (!isPasswordValid) {
      throw new Error('Invalid email or password');
    }

    return existingUser[0];
  } catch (error) {
    logger.error(`Error authenticating user: ${error}`);
    throw error;
  }
};
