import NextAuth from 'next-auth';
import Credentials from 'next-auth/providers/credentials';
import { z } from 'zod';
import bcrypt from 'bcryptjs';
import postgres from 'postgres';

import { authConfig } from './auth.config';
import type { User } from '@/app/lib/definitions';
 
const sql = postgres(process.env.POSTGRES_URL!, { ssl: 'require' });
 
async function getUser(email: string): Promise<User | undefined> {
  try {
    const user = await sql<User[]>`SELECT * FROM users WHERE email=${email}`;
    console.log('getUser: user:', user);
    return user[0];
  } catch (error) {
    console.error('Failed to fetch user:', error);
    throw new Error('Failed to fetch user.');
  }
}
 
export const { auth, signIn, signOut } = NextAuth({
  ...authConfig,
  providers: [Credentials({
    async authorize(credentials) {
      const parsedCredentials = z
        .object({ email: z.string().email(), password: z.string().min(6) })
        .safeParse(credentials);
      console.log('auth: parsedCredentials:', parsedCredentials);
      if (parsedCredentials.success) {
        const { email, password } = parsedCredentials.data;
        const user = await getUser(email);
        console.log('auth: got user:', user);
        if (!user) return null;
        const passwordsMatch = await bcrypt.compare(password, user.password);
        console.log('auth: passwordsMatch:', passwordsMatch);
        if (passwordsMatch) return user;
      }
      console.log('Invalid credentials');
      return null;
    },
  })],
});