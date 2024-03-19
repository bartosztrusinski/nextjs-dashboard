import { User } from '@/app/lib/definitions';
import { authConfig } from '@/auth.config';
import { sql } from '@vercel/postgres';
import bcrypt from 'bcrypt';
import NextAuth from 'next-auth';
import Credentials from 'next-auth/providers/credentials';
import { z } from 'zod';

const getUserByEmail = async (email: string): Promise<User | undefined> => {
  try {
    const user = await sql`SELECT * FROM users WHERE email = ${email}`;
    return user.rows[0] as User;
  } catch (error) {
    console.error('Failed to fetch user:', error);
    throw new Error('Failed to fetch user.');
  }
};

export const { auth, signIn, signOut } = NextAuth({
  ...authConfig,
  providers: [
    Credentials({
      async authorize(credentials) {
        const parsedCredentials = z
          .object({ email: z.string().email(), password: z.string().min(6) })
          .safeParse(credentials);

        if (!parsedCredentials.success) return null;

        const { email, password } = parsedCredentials.data;
        const user = await getUserByEmail(email);

        if (!user) return null;

        const passwordsMatch = bcrypt.compare(password, user.password);

        if (!passwordsMatch) return null;

        return user;
      },
    }),
  ],
});
