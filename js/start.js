import { execSync } from 'child_process';

const url = "https://github.com/aidansteele/gha-stats/releases/download/v0.2.0/gha-stats_0.2.0_linux_amd64.tar.gz";
execSync(`curl -o /tmp/gha-stats.tgz -L ${url}`);
execSync(`sudo tar -C /usr/bin -xvf /tmp/gha-stats.tgz`);
execSync(`gha-stats start 5s`);
