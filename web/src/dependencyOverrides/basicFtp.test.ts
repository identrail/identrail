import { createRequire } from "node:module";
import type { Writable } from "node:stream";
import { afterEach, describe, expect, it, vi } from "vitest";

const require = createRequire(import.meta.url);
const { getUri } = require("get-uri") as {
  getUri: (uri: URL) => Promise<NodeJS.ReadableStream & AsyncIterable<Buffer>>;
};
const { Client } = require("basic-ftp");
const { version: basicFtpVersion } = require("basic-ftp/package.json");

afterEach(() => vi.restoreAllMocks());

describe("basic-ftp 6 override used by get-uri", () => {
  it("keeps get-uri's FTP adapter working with the resolved basic-ftp client", async () => {
    expect(basicFtpVersion).toMatch(/^6\./);

    const access = vi.spyOn(Client.prototype, "access").mockImplementation(async function () {
      expect(this.options.allowSeparateTransferHost).toBe(false);
      return {};
    });
    vi.spyOn(Client.prototype, "lastMod").mockResolvedValue(new Date("2026-10-05T12:00:00Z"));
    vi.spyOn(Client.prototype, "downloadTo").mockImplementation(async (destination) => {
      (destination as Writable).end("PAC file contents");
      return {};
    });
    vi.spyOn(Client.prototype, "close").mockImplementation(() => {});

    const stream = await getUri(new URL("ftp://proxy.example.test:2121/proxy.pac"));
    const chunks: Buffer[] = [];
    for await (const chunk of stream) chunks.push(Buffer.from(chunk));

    expect(Buffer.concat(chunks).toString()).toBe("PAC file contents");
    expect(access).toHaveBeenCalledWith(
      expect.objectContaining({ host: "proxy.example.test", port: 2121 }),
    );
  });

  it("rejects a different passive data host by default", async () => {
    const client = new Client();
    const ftp = {
      log: () => {},
      request: async (command: string) => ({
        message:
          command === "EPSV"
            ? "500 unsupported"
            : "227 Entering Passive Mode (192,168,1,20,4,1)",
      }),
      socket: { remoteAddress: "192.168.1.10" },
    };

    await expect(client.prepareTransfer(ftp)).rejects.toThrow(
      /PASV returned another host .* basic-ftp disables this feature by default for security reasons/,
    );
  });
});
