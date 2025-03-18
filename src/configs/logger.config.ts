export default () => ({
  logger: {
    redact: {
      fields: ['password', 'secret', 'token'],
    },
  },
});
