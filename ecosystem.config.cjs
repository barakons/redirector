module.exports = {
  apps: [
    {
      name: "redirector",
      script: "server.js",
      instances: 1,
      exec_mode: "fork",
      watch: false,
      autorestart: true,
      max_restarts: 10,
      env: {
        NODE_ENV: "production",
        PORT: 3461,
        DB_PATH: "./data.db",
      },
    },
  ],
};
