import { hashSecret, verifySecret } from './crypto';
import type { Client, ClientSource, User, UserSource } from './types';

export interface StaticUser extends User {
  // scrypt hash from `oidc-rbac hash`.
  passwordHash: string;
}

// A fixed list of Users, e.g. from the config file. Roles change on restart.
export function staticUsers(users: StaticUser[]): UserSource {
  const strip = ({ passwordHash: _, ...user }: StaticUser): User => user;
  return {
    async findById(sub) {
      const user = users.find((u) => u.sub === sub);
      return user && strip(user);
    },
    async authenticate(username, password) {
      const user = users.find((u) => u.username === username);
      // Hash even when the user is unknown so response time doesn't reveal valid usernames.
      const valid = verifySecret(password, user?.passwordHash ?? DUMMY_HASH);
      return user && valid ? strip(user) : undefined;
    },
  };
}

export function staticClients(clients: Client[]): ClientSource {
  return {
    async findById(clientId) {
      return clients.find((c) => c.clientId === clientId);
    },
  };
}

const DUMMY_HASH = hashSecret('not-a-real-password');
