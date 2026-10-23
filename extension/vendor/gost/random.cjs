// Local adapter: never fall back to Math.random or timing-based entropy.
module.exports = class BrowserRandom {
  getRandomValues(bytes) {
    if (!globalThis.crypto?.getRandomValues) throw new Error('Secure random source unavailable');
    return globalThis.crypto.getRandomValues(bytes);
  }
};
