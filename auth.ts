import NextAuth, { DefaultSession } from "next-auth";
import GitHubProvider from "next-auth/providers/github";
import GoogleProvider from "next-auth/providers/google";
import CredentialsProvider from "next-auth/providers/credentials";
import bcrypt from "bcryptjs";
import dbConnect from "@/lib/dbConnect";
import User from "@/app/models/User";

export type ExtendedUser = DefaultSession["user"] & {
  provider: string;
};

declare module "next-auth" {
  /**
   * Returned by `auth`, `useSession`, `getSession` and received as a prop on the `SessionProvider` React Context
   */
  interface Session {
    user: ExtendedUser;
  }
}

export const { handlers, signIn, signOut, auth } = NextAuth({
  providers: [
    CredentialsProvider({
      name: "Credentials",
      async authorize(credentials) {
        const { email, password, rememberMe } = credentials || {};

        if (!email || !password) {
          throw new Error("Missing credentials");
        }

        await dbConnect();
        const user = await User.findOne({ email });

        if (!user || typeof password !== "string") {
          throw new Error("Invalid credentials");
        }

        if (user && bcrypt.compareSync(password, user.password)) {
          return {
            id: user._id.toString(),
            name: user.name,
            email: user.email,
            rememberMe,
          };
        }

        throw new Error("Invalid credentials");
      },
    }),
    GoogleProvider({
      clientId: process.env.GOOGLE_CLIENT_ID as string,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET as string,
      authorization: {
        params: {
          prompt: "consent",
          access_type: "offline",
          response_type: "code",
        },
      },
    }),
    GitHubProvider({
      clientId: process.env.GITHUB_CLIENT_ID as string,
      clientSecret: process.env.GITHUB_CLIENT_SECRET as string,
    }),
  ],
  session: {
    strategy: "jwt",
    maxAge: 30 * 24 * 60 * 60, // 30 days
  },
  callbacks: {
    async signIn({ user, account, profile }) {
      if (!profile) {
        console.error("No profile data received");
        return false;
      }

      try {
        await dbConnect();

        if (account?.provider === "google") {
          const existingUser = await User.findOne({ email: profile.email });

          if (!existingUser) {
            const newUser = new User({
              name: profile.name,
              email: profile.email,
              avatar: profile.picture,
              googleId: profile.sub,
              coursesBought: [],
            });
            await newUser.save();
          } else {
            // Update existing user's Google ID if not set
            if (!existingUser.googleId) {
              existingUser.googleId = profile.sub;
              existingUser.avatar = profile.picture || existingUser.avatar;
              await existingUser.save();
            }
          }
        }

        // Similar logic for GitHub...
        if (account?.provider === "github") {
          const existingUser = await User.findOne({
            $or: [{ githubId: profile.id }, { email: profile.email }],
          });

          if (!existingUser) {
            const newUser = new User({
              name: profile.name || profile.login,
              email: profile.email || `${profile.id}@github.com`,
              avatar: profile.avatar_url,
              githubId: profile.id,
              coursesBought: [],
            });
            await newUser.save();
          } else {
            // Update existing user's GitHub ID if not set
            if (!existingUser.githubId) {
              existingUser.githubId = profile.id;
              existingUser.avatar = profile.avatar_url || existingUser.avatar;
              await existingUser.save();
            }
          }
        }

        return true;
      } catch (error) {
        console.error("Error in signIn callback:", error);
        return false;
      }
    },
    async jwt({ token, user, account, profile }) {
      try {
        await dbConnect();
        let dbUser = null;

        if (account?.provider === "google" && profile?.sub) {
          dbUser = await User.findOne({ googleId: profile.sub });
        } else if (account?.provider === "github" && profile?.id) {
          dbUser = await User.findOne({ githubId: profile.id });
        } else if (user?.email) {
          dbUser = await User.findOne({ email: user.email });
        }

        if (dbUser) {
          token.id = dbUser._id.toString();
          token.image = dbUser.avatar || token.picture || null;
        } else if (user?.id) {
          token.id = user.id;
        }

        if (!token.id) {
          throw new Error("Invalid user data in JWT callback");
        }

        token.provider = account?.provider || null;
        return token;
      } catch (error) {
        console.error("Error in jwt callback:", error);
        throw error;
      }
    },
    async session({ session, token }: { session: any; token: any }) {
      if (!token) {
        return session;
      }

      try {
        session.user = {
          id: String(token.id || ""),
          name: token.name || "",
          email: String(token.email || ""),
          image: String(token.image || ""),
          provider: String(token.provider || ""),
        };

        // Calculate expiration time based on remember me preference
        const THIRTY_DAYS_MS = 30 * 24 * 60 * 60 * 1000;
        const ONE_HOUR_MS = 60 * 60 * 1000;

        // Create Date object for expiration
        const expirationTime = new Date(
          Date.now() + (token.rememberMe ? THIRTY_DAYS_MS : ONE_HOUR_MS)
        );

        // Assign directly without conversion - it's already a Date object
        session.expires = expirationTime;

        return session;
      } catch (error) {
        console.error("Error updating session:", error);
        throw new Error("Failed to update session");
      }
    },
  },
  pages: {
    signIn: "/login",
    error: "/auth/error", // Add this line to handle auth errors
  },
  debug: process.env.NODE_ENV === "development",
  secret: process.env.AUTH_SECRET,
});
