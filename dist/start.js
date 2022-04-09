// js/start.js
var import_child_process = require("child_process");
var url = "https://github.com/aidansteele/gha-stats/releases/download/v0.1.0/gha-stats_0.1.0_linux_amd64.tar.gz";
(0, import_child_process.execSync)(`curl -o /tmp/gha-stats.tgz -L ${url}`);
(0, import_child_process.execSync)(`sudo tar -C /usr/bin -xvf /tmp/gha-stats.tgz`);
(0, import_child_process.execSync)(`gha-stats start 5s`);
