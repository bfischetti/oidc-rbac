export interface User {
  sub: string;
  username: string;
  name?: string;
  email?: string;
  roles: string[];
}

export interface Client {
  clientId: string;
  name: string;
  // scrypt hash from `oidc-rbac hash`. Present for Confidential Clients, absent for Public Clients.
  secretHash?: string;
  redirectUris: string[];
}

// Where Users come from. Plug in your own database by implementing this.
export interface UserSource {
  findById(sub: string): Promise<User | undefined>;
  // Returns the User when the credentials are valid, otherwise undefined.
  authenticate(username: string, password: string): Promise<User | undefined>;
}

export interface ClientSource {
  findById(clientId: string): Promise<Client | undefined>;
}

export interface Logger {
  info(message: string): void;
  warn(message: string): void;
  error(message: string): void;
}

export const silentLogger: Logger = { info() {}, warn() {}, error() {} };

export const consoleLogger = (prefix = '[oidc-rbac]'): Logger => ({
  info: (m) => console.log(`${prefix} ${m}`),
  warn: (m) => console.warn(`${prefix} ${m}`),
  error: (m) => console.error(`${prefix} ${m}`),
});
