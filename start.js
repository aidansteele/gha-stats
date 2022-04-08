import { execSync } from 'child_process';

const url = "https://github.com/aidansteele/gha-stats/releases/download/v0.1.0/gha-stats_0.1.0_linux_amd64.tar.gz";
execSync(`curl -o /tmp/gha-stats.tgz -L ${url}`);
execSync(`tar -xvf -C /usr/bin /tmp/gha-stats.tgz`);
execSync(`gha-stats start`);
