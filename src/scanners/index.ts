import { Scanner } from "../types.js";
import { scanShellCommands } from "./shell-commands.js";
import { scanCurlPipe } from "./curl-pipe.js";
import { scanObfuscation } from "./obfuscation.js";
import { scanSecrets } from "./secrets.js";
import { scanDomains } from "./domains.js";
import { scanSocialEngineering } from "./social-engineering.js";

export const ALL_SCANNERS: Scanner[] = [
  scanShellCommands,
  scanCurlPipe,
  scanObfuscation,
  scanSecrets,
  scanDomains,
  scanSocialEngineering,
];

export {
  scanShellCommands,
  scanCurlPipe,
  scanObfuscation,
  scanSecrets,
  scanDomains,
  scanSocialEngineering,
};
