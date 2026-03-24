"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.scanSocialEngineering = exports.scanDomains = exports.scanSecrets = exports.scanObfuscation = exports.scanCurlPipe = exports.scanShellCommands = exports.ALL_SCANNERS = void 0;
const shell_commands_js_1 = require("./shell-commands.js");
Object.defineProperty(exports, "scanShellCommands", { enumerable: true, get: function () { return shell_commands_js_1.scanShellCommands; } });
const curl_pipe_js_1 = require("./curl-pipe.js");
Object.defineProperty(exports, "scanCurlPipe", { enumerable: true, get: function () { return curl_pipe_js_1.scanCurlPipe; } });
const obfuscation_js_1 = require("./obfuscation.js");
Object.defineProperty(exports, "scanObfuscation", { enumerable: true, get: function () { return obfuscation_js_1.scanObfuscation; } });
const secrets_js_1 = require("./secrets.js");
Object.defineProperty(exports, "scanSecrets", { enumerable: true, get: function () { return secrets_js_1.scanSecrets; } });
const domains_js_1 = require("./domains.js");
Object.defineProperty(exports, "scanDomains", { enumerable: true, get: function () { return domains_js_1.scanDomains; } });
const social_engineering_js_1 = require("./social-engineering.js");
Object.defineProperty(exports, "scanSocialEngineering", { enumerable: true, get: function () { return social_engineering_js_1.scanSocialEngineering; } });
exports.ALL_SCANNERS = [
    shell_commands_js_1.scanShellCommands,
    curl_pipe_js_1.scanCurlPipe,
    obfuscation_js_1.scanObfuscation,
    secrets_js_1.scanSecrets,
    domains_js_1.scanDomains,
    social_engineering_js_1.scanSocialEngineering,
];
