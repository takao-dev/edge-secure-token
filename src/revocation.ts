/**
 * Token revocation (blacklist) store for edge-secure-token.
 * Allows immediate revocation of tokens prior to their natural expiration.
 * Zero Runtime Dependencies.
 */

export interface RevocationStore {
  revoke(jti: string, expSec: number): Promise<void> | void;
  isRevoked(jti: string): Promise<boolean> | boolean;
}

/**
 * In-memory token revocation store with automatic cleanup of expired tokens.
 */
export class MemoryRevocationStore implements RevocationStore {
  private readonly revoked = new Map<string, number>();

  revoke(jti: string, expSec: number): void {
    this.cleanExpired();
    this.revoked.set(jti, expSec);
  }

  isRevoked(jti: string): boolean {
    const exp = this.revoked.get(jti);
    if (!exp) return false;

    const nowSec = Math.floor(Date.now() / 1000);
    if (nowSec >= exp) {
      this.revoked.delete(jti);
      return false;
    }

    return true;
  }

  private cleanExpired(): void {
    const nowSec = Math.floor(Date.now() / 1000);
    for (const [jti, exp] of this.revoked.entries()) {
      if (nowSec >= exp) {
        this.revoked.delete(jti);
      }
    }
  }

  clear(): void {
    this.revoked.clear();
  }
}
