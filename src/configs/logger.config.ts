export default () => ({
  logger: {
    redact: {
      fields: ['password', 'secret', 'accessToken', 'refreshToken'],
    },
  },
});
