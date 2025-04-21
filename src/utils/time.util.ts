export const convertToSeconds = (time: string): number => {
  const timeValue = parseInt(time.slice(0, -1), 10);
  const timeUnit = time.slice(-1);
  switch (timeUnit) {
    case 's': // seconds
      return timeValue;
    case 'm': // minutes
      return timeValue * 60;
    case 'h': // hours
      return timeValue * 60 * 60;
    case 'd': // days
      return timeValue * 24 * 60 * 60;
    default:
      throw new Error(
        "Invalid time format. Use 's', 'm', 'h' or 'd' (e.g., '30m' or '1h').",
      );
  }
};
