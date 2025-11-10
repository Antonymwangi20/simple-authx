export const defaultHooks = {
  async onRegister(user) {
    console.log(`[hook] User registered: ${user.username}`);
  },
  async onLogin(user) {
    console.log(`[hook] User logged in: ${user.username}`);
  },
};
